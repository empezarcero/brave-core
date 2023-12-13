#ifndef BRAVE_THIRD_PARTY_BLINK_RENDERER_CORE_BRAVE_PAGE_GRAPH_SCRIPTS_SCRIPT_SIGNATURE_H_
#define BRAVE_THIRD_PARTY_BLINK_RENDERER_CORE_BRAVE_PAGE_GRAPH_SCRIPTS_SCRIPT_SIGNATURE_H_

#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "base/uuid.h"
#include <optional>

namespace blink {
class CORE_EXPORT ScriptSignature
{
public:
  ScriptSignature(const WTF::String& script_text);

  bool IsSignatureValid() const {
    return _is_valid;
  }

  bool IsSigned() const {
    return _is_signed;
  }

  absl::optional<std::vector<uint8_t>> getSignature() const {
    return _signature;
  }

private:
  std::optional<WTF::String> GetBase64FromScriptByToken(const WTF::String& script_text, const WTF::StringView& token);
  absl::optional<std::vector<uint8_t>> _signature;
  bool _is_signed;
  bool _is_valid;
};
} // namespace blink

#endif //BRAVE_THIRD_PARTY_BLINK_RENDERER_CORE_BRAVE_PAGE_GRAPH_SCRIPTS_SCRIPT_SIGNATURE_H_