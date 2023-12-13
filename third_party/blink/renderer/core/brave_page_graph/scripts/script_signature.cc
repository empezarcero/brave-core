#include "brave/third_party/blink/renderer/core/brave_page_graph/scripts/script_signature.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "base/uuid.h"
#include "base/base64.h"
#include "base/logging.h"
#include "base/hash/md5_boringssl.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "crypto/signature_verifier.h"

namespace blink {

ScriptSignature::ScriptSignature(const WTF::String& script_text) : _is_signed(false), _is_valid(false)
{
  static constexpr char SIGNATURE_TOKEN[] = "SIGNATURE: ";
  static constexpr char CERTIFICATE_TOKEN[] = "CERTIFICATE: ";

  if (script_text.empty()) {
    return;
  }
  VLOG(1) << "Checking script signature on non-empty script";

  auto b64_signature = GetBase64FromScriptByToken(script_text, SIGNATURE_TOKEN);
  if (!b64_signature.has_value()) {
    return;
  }
  VLOG(1) << "Base64 Signature" << b64_signature.value();

  auto b64_cert = GetBase64FromScriptByToken(script_text, CERTIFICATE_TOKEN);
  if (!b64_cert.has_value()) {
    return;
  }
  VLOG(1) << "Base64 CERT" << b64_cert.value();

  auto signature = base::Base64Decode(b64_signature.value().Ascii());
  if (!signature.has_value()) {
    VLOG(1) << "Signature decoding failed";
    return;
  }

  auto certificate = base::Base64Decode(b64_cert.value().Ascii());
  if (!certificate.has_value()) {
    VLOG(1) << "Certificated decoding failed";
    return;
  }

  auto start_of_data = std::max(script_text.Find(SIGNATURE_TOKEN), script_text.Find(CERTIFICATE_TOKEN));
  start_of_data = script_text.Find("*/", start_of_data);
  if (start_of_data == kNotFound) {
    VLOG(1) << "No end of comment found";
    return;
  }
  start_of_data += 2;
  while((script_text[start_of_data] == '\n' || script_text[start_of_data] == '\r') && (start_of_data < (script_text.length() - 1))) {
    start_of_data++;
  }

  crypto::SignatureVerifier verifier;
  if (!verifier.VerifyInit(crypto::SignatureVerifier::SignatureAlgorithm::RSA_PSS_SHA256, 
      signature.value(), 
      certificate.value())) {
    VLOG(1) << "VerifyInit failed";
    return;
  }

  _is_signed = true;
  _signature = signature.value();

  auto data_to_verify =script_text.Right(script_text.length()-start_of_data);
  VLOG(1) << "Script to verify: " << data_to_verify;
  base::MD5Digest script_md5_hash;
  MD5(data_to_verify.Span8().data(), data_to_verify.length(), script_md5_hash.a);
  VLOG(1) << "Script MD5 hash: " << base::ToLowerASCII(base::HexEncode(script_md5_hash.a, sizeof(script_md5_hash.a)));
  verifier.VerifyUpdate(data_to_verify.Span8());

  _is_valid = verifier.VerifyFinal();
}

std::optional<WTF::String> ScriptSignature::GetBase64FromScriptByToken(
    const WTF::String& script_text, 
    const WTF::StringView& token)
{
  auto token_pos = script_text.Find(token);
  if (token_pos == kNotFound) {
    return std::nullopt;
  }

  auto base64_pos = token_pos + token.length();

  auto base64_len = script_text.Substring(base64_pos).find(' ');
  if (base64_len == kNotFound) {
    return std::nullopt;
  }

  return script_text.Substring(base64_pos, base64_len);
}
} // namespace blink