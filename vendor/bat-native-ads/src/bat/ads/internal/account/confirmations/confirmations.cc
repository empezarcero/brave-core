/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ads/internal/account/confirmations/confirmations.h"

#include <cstdint>
#include <vector>

#include "base/check_op.h"
#include "base/guid.h"
#include "base/json/json_writer.h"
#include "base/time/time.h"
#include "base/values.h"
#include "bat/ads/ad_type.h"
#include "bat/ads/confirmation_type.h"
#include "bat/ads/internal/account/account_util.h"
#include "bat/ads/internal/account/confirmations/confirmations_user_data_builder.h"
#include "bat/ads/internal/account/utility/redeem_unblinded_token/create_confirmation_util.h"
#include "bat/ads/internal/account/utility/redeem_unblinded_token/redeem_unblinded_token.h"
#include "bat/ads/internal/ads_client_helper.h"
#include "bat/ads/internal/base/logging_util.h"
#include "bat/ads/internal/base/time/time_formatting_util.h"
#include "bat/ads/internal/deprecated/confirmations/confirmation_state_manager.h"
#include "bat/ads/internal/privacy/challenge_bypass_ristretto/blinded_token.h"
#include "bat/ads/internal/privacy/challenge_bypass_ristretto/blinded_token_util.h"
#include "bat/ads/internal/privacy/challenge_bypass_ristretto/token.h"
#include "bat/ads/internal/privacy/tokens/token_generator_interface.h"
#include "bat/ads/internal/privacy/tokens/unblinded_payment_tokens/unblinded_payment_token_info.h"
#include "bat/ads/internal/privacy/tokens/unblinded_payment_tokens/unblinded_payment_tokens.h"
#include "bat/ads/internal/privacy/tokens/unblinded_tokens/unblinded_token_info.h"
#include "bat/ads/internal/privacy/tokens/unblinded_tokens/unblinded_tokens.h"
#include "bat/ads/pref_names.h"
#include "bat/ads/transaction_info.h"

namespace ads {

namespace {
constexpr base::TimeDelta kRetryAfter = base::Seconds(15);
}  // namespace

Confirmations::Confirmations(privacy::TokenGeneratorInterface* token_generator)
    : token_generator_(token_generator),
      redeem_unblinded_token_(std::make_unique<RedeemUnblindedToken>()) {
  DCHECK(token_generator_);

  redeem_unblinded_token_->set_delegate(this);
}

Confirmations::~Confirmations() {
  delegate_ = nullptr;
}

void Confirmations::Confirm(const TransactionInfo& transaction) {
  DCHECK(transaction.IsValid());

  BLOG(1, "Confirming " << transaction.confirmation_type << " for "
                        << transaction.ad_type << " with transaction id "
                        << transaction.id << " and creative instance id "
                        << transaction.creative_instance_id);

  const base::Time now = base::Time::Now();

  const ConfirmationsUserDataBuilder user_data_builder(
      now, transaction.creative_instance_id, transaction.confirmation_type);
  user_data_builder.Build([=](const base::Value& user_data) {
    const ConfirmationInfo& confirmation = CreateConfirmation(
        now, transaction.id, transaction.creative_instance_id,
        transaction.confirmation_type, transaction.ad_type, user_data);

    redeem_unblinded_token_->Redeem(confirmation);
  });
}

void Confirmations::ProcessRetryQueue() {
  if (retry_timer_.IsRunning()) {
    return;
  }

  Retry();
}

///////////////////////////////////////////////////////////////////////////////

void Confirmations::Retry() {
  const ConfirmationList& failed_confirmations =
      ConfirmationStateManager::Get()->GetFailedConfirmations();
  if (failed_confirmations.empty()) {
    BLOG(1, "No failed confirmations to retry");
    return;
  }

  DCHECK(!retry_timer_.IsRunning());
  const base::Time retry_at = retry_timer_.StartWithPrivacy(
      FROM_HERE, kRetryAfter,
      base::BindOnce(&Confirmations::OnRetry, base::Unretained(this)));

  BLOG(1,
       "Retry sending failed confirmations " << FriendlyDateAndTime(retry_at));
}

void Confirmations::OnRetry() {
  const ConfirmationList& failed_confirmations =
      ConfirmationStateManager::Get()->GetFailedConfirmations();
  DCHECK(!failed_confirmations.empty());

  const ConfirmationInfo& confirmation = failed_confirmations.front();

  RemoveFromRetryQueue(confirmation);

  redeem_unblinded_token_->Redeem(confirmation);
}

void Confirmations::StopRetrying() {
  retry_timer_.Stop();
}

ConfirmationInfo Confirmations::CreateConfirmation(
    const base::Time time,
    const std::string& transaction_id,
    const std::string& creative_instance_id,
    const ConfirmationType& confirmation_type,
    const AdType& ad_type,
    const base::Value& user_data) const {
  DCHECK(!transaction_id.empty());
  DCHECK(!creative_instance_id.empty());
  DCHECK_NE(ConfirmationType::kUndefined, confirmation_type.value());
  DCHECK_NE(AdType::kUndefined, ad_type.value());

  ConfirmationInfo confirmation;

  confirmation.id = base::GUID::GenerateRandomV4().AsLowercaseString();
  confirmation.transaction_id = transaction_id;
  confirmation.creative_instance_id = creative_instance_id;
  confirmation.type = confirmation_type;
  confirmation.ad_type = ad_type;
  confirmation.created_at = time;

  if (ShouldRewardUser() &&
      !ConfirmationStateManager::Get()->get_unblinded_tokens()->IsEmpty()) {
    const privacy::UnblindedTokenInfo& unblinded_token =
        ConfirmationStateManager::Get()->get_unblinded_tokens()->GetToken();

    confirmation.unblinded_token = unblinded_token;

    const std::vector<privacy::cbr::Token> tokens =
        token_generator_->Generate(1);
    DCHECK(!tokens.empty());
    confirmation.payment_token = tokens.front();

    const std::vector<privacy::cbr::BlindedToken> blinded_tokens =
        privacy::cbr::BlindTokens(tokens);
    DCHECK(!blinded_tokens.empty());
    confirmation.blinded_payment_token = blinded_tokens.front();

    std::string json;
    base::JSONWriter::Write(user_data, &json);
    confirmation.user_data = json;

    const std::string& payload = CreateConfirmationRequestDTO(confirmation);
    confirmation.credential = CreateCredential(unblinded_token, payload);

    ConfirmationStateManager::Get()->get_unblinded_tokens()->RemoveToken(
        unblinded_token);
    ConfirmationStateManager::Get()->Save();
  }

  return confirmation;
}

void Confirmations::CreateNewConfirmationAndAppendToRetryQueue(
    const ConfirmationInfo& confirmation) {
  DCHECK(confirmation.IsValid());

  if (ConfirmationStateManager::Get()->get_unblinded_tokens()->IsEmpty()) {
    AppendToRetryQueue(confirmation);
    return;
  }

  const ConfirmationsUserDataBuilder user_data_builder(
      confirmation.created_at, confirmation.creative_instance_id,
      confirmation.type);
  user_data_builder.Build([=](const base::Value& user_data) {
    const ConfirmationInfo& new_confirmation =
        CreateConfirmation(confirmation.created_at, confirmation.transaction_id,
                           confirmation.creative_instance_id, confirmation.type,
                           confirmation.ad_type, user_data);

    AppendToRetryQueue(new_confirmation);
  });
}

void Confirmations::AppendToRetryQueue(const ConfirmationInfo& confirmation) {
  DCHECK(confirmation.IsValid());

  ConfirmationStateManager::Get()->AppendFailedConfirmation(confirmation);
  ConfirmationStateManager::Get()->Save();

  BLOG(1, "Added " << confirmation.type << " confirmation for "
                   << confirmation.ad_type << " with id " << confirmation.id
                   << ", transaction id" << confirmation.transaction_id
                   << " and creative instance id "
                   << confirmation.creative_instance_id
                   << " to the confirmations queue");
}

void Confirmations::RemoveFromRetryQueue(const ConfirmationInfo& confirmation) {
  DCHECK(confirmation.IsValid());

  if (!ConfirmationStateManager::Get()->RemoveFailedConfirmation(
          confirmation)) {
    BLOG(0, "Failed to remove " << confirmation.type << " confirmation for "
                                << confirmation.ad_type << " with id "
                                << confirmation.id << ", transaction id "
                                << confirmation.transaction_id
                                << " and creative instance id "
                                << confirmation.creative_instance_id
                                << " from the confirmations queue");

    return;
  }

  BLOG(1, "Removed " << confirmation.type << " confirmation for "
                     << confirmation.ad_type << " with id " << confirmation.id
                     << ", transaction id " << confirmation.transaction_id
                     << " and creative instance id "
                     << confirmation.creative_instance_id
                     << " from the confirmations queue");

  ConfirmationStateManager::Get()->Save();
}

void Confirmations::OnDidSendConfirmation(
    const ConfirmationInfo& confirmation) {
  BLOG(1, "Successfully sent " << confirmation.type << " confirmation for "
                               << confirmation.ad_type << " with id "
                               << confirmation.id << ", transaction id "
                               << confirmation.transaction_id
                               << " and creative instance id "
                               << confirmation.creative_instance_id);

  if (delegate_) {
    delegate_->OnDidConfirm(confirmation);
  }

  StopRetrying();

  ProcessRetryQueue();
}

void Confirmations::OnFailedToSendConfirmation(
    const ConfirmationInfo& confirmation,
    const bool should_retry) {
  BLOG(1, "Failed to send " << confirmation.type << " confirmation for "
                            << confirmation.ad_type << " with id "
                            << confirmation.id << ", transaction id "
                            << confirmation.transaction_id
                            << " and creative instance id "
                            << confirmation.creative_instance_id);

  if (should_retry) {
    AppendToRetryQueue(confirmation);
  }

  if (delegate_) {
    delegate_->OnFailedToConfirm(confirmation);
  }

  ProcessRetryQueue();
}

void Confirmations::OnDidRedeemUnblindedToken(
    const ConfirmationInfo& confirmation,
    const privacy::UnblindedPaymentTokenInfo& unblinded_payment_token) {
  if (ConfirmationStateManager::Get()
          ->get_unblinded_payment_tokens()
          ->TokenExists(unblinded_payment_token)) {
    BLOG(1, "Unblinded payment token is a duplicate");
    OnFailedToRedeemUnblindedToken(confirmation, /* should_retry */ false);
    return;
  }

  ConfirmationStateManager::Get()->get_unblinded_payment_tokens()->AddTokens(
      {unblinded_payment_token});
  ConfirmationStateManager::Get()->Save();

  const int unblinded_payment_tokens_count =
      ConfirmationStateManager::Get()->get_unblinded_payment_tokens()->Count();

  const base::Time next_token_redemption_at =
      AdsClientHelper::Get()->GetTimePref(prefs::kNextTokenRedemptionAt);

  BLOG(1, "Successfully redeemed unblinded token for "
              << confirmation.ad_type << " with confirmation id "
              << confirmation.id << ", transaction id "
              << confirmation.transaction_id << ", creative instance id "
              << confirmation.creative_instance_id << " and "
              << confirmation.type << ". You now have "
              << unblinded_payment_tokens_count
              << " unblinded payment tokens which will be redeemed "
              << FriendlyDateAndTime(next_token_redemption_at));

  if (delegate_) {
    delegate_->OnDidConfirm(confirmation);
  }

  StopRetrying();

  ProcessRetryQueue();
}

void Confirmations::OnFailedToRedeemUnblindedToken(
    const ConfirmationInfo& confirmation,
    const bool should_retry) {
  BLOG(1, "Failed to redeem unblinded token for "
              << confirmation.ad_type << " with confirmation id "
              << confirmation.id << ", transaction id "
              << confirmation.transaction_id << ", creative instance id "
              << confirmation.creative_instance_id << " and "
              << confirmation.type);

  if (should_retry) {
    if (!confirmation.was_created) {
      CreateNewConfirmationAndAppendToRetryQueue(confirmation);
    } else {
      AppendToRetryQueue(confirmation);
    }
  }

  if (delegate_) {
    delegate_->OnFailedToConfirm(confirmation);
  }

  ProcessRetryQueue();
}

}  // namespace ads
