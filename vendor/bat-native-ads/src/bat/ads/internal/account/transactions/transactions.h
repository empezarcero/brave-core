/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_VENDOR_BAT_NATIVE_ADS_SRC_BAT_ADS_INTERNAL_ACCOUNT_TRANSACTIONS_TRANSACTIONS_H_
#define BRAVE_VENDOR_BAT_NATIVE_ADS_SRC_BAT_ADS_INTERNAL_ACCOUNT_TRANSACTIONS_TRANSACTIONS_H_

#include <functional>
#include <string>

#include "bat/ads/transaction_info.h"

namespace base {
class Time;
}  // namespace base

namespace ads {

class AdType;
class ConfirmationType;

namespace transactions {

using AddCallback =
    std::function<void(const bool, const TransactionInfo& transaction)>;

using GetCallback = std::function<void(const bool, const TransactionList&)>;

using RemoveAllCallback = std::function<void(const bool)>;

TransactionInfo Add(const std::string& creative_instance_id,
                    const double value,
                    const AdType& ad_type,
                    const ConfirmationType& confirmation_type,
                    AddCallback callback);

void GetForDateRange(const base::Time from_time,
                     const base::Time to_time,
                     GetCallback callback);

void RemoveAll(RemoveAllCallback callback);

}  // namespace transactions
}  // namespace ads

#endif  // BRAVE_VENDOR_BAT_NATIVE_ADS_SRC_BAT_ADS_INTERNAL_ACCOUNT_TRANSACTIONS_TRANSACTIONS_H_
