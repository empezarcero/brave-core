/* Copyright (c) 2022 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_COMPONENTS_P3A_BRAVE_P3A_MESSAGE_MANAGER_H_
#define BRAVE_COMPONENTS_P3A_BRAVE_P3A_MESSAGE_MANAGER_H_

#include <memory>
#include <string>

#include "base/callback.h"
#include "base/containers/flat_map.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece_forward.h"
#include "base/timer/timer.h"
#include "brave/components/p3a/brave_p3a_config.h"
#include "brave/components/p3a/brave_p3a_metric_log_store.h"
#include "brave/components/p3a/metric_log_type.h"
#include "brave/components/p3a/p3a_message.h"
#include "third_party/abseil-cpp/absl/types/optional.h"

class PrefService;

namespace network {
class SharedURLLoaderFactory;
}

namespace brave {

struct BraveP3AConfig;

class BraveP3AUploader;
class BraveP3AStarLogStore;
class BraveP3ARotationScheduler;
class BraveP3AScheduler;
class BraveP3AStar;
class BraveP3AUploader;

struct RandomnessServerInfo;

// The message manager has multiple roles related to handling/reporting metric
// values. Metric updates received upstream from the BraveP3AService are stored
// in their appropriate BraveP3ALogStore instances. The BraveP3AScheduler calls
// methods in this class via callbacks and propagates metric upload to the
// BraveP3AUploader. The BraveP3ARotationScheduler also calls methods in this
// class to handle reporting period rotation. STAR message preparation is also
// triggered from this class.
class BraveP3AMessageManager : public BraveP3AMetricLogStore::Delegate {
 public:
  using IsDynamicMetricRegisteredCallback =
      base::RepeatingCallback<bool(const std::string& histogram_name)>;
  class Delegate {
   public:
    virtual absl::optional<MetricLogType> GetDynamicMetricLogType(
        const std::string& histogram_name) const = 0;
    virtual void OnRotation(MetricLogType log_type, bool is_star) = 0;
    // A metric "cycle" is a transmission to the P3A JSON server,
    // or a STAR preparation for the current epoch.
    virtual void OnMetricCycled(const std::string& histogram_name,
                                bool is_star) = 0;
    virtual ~Delegate() {}
  };
  BraveP3AMessageManager(PrefService* local_state,
                         BraveP3AConfig* config,
                         Delegate* delegate,
                         std::string channel,
                         std::string week_of_install);
  ~BraveP3AMessageManager() override;

  static void RegisterPrefs(PrefRegistrySimple* registry);

  void Init(scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory);

  void UpdateMetricValue(base::StringPiece histogram_name, size_t bucket);

  void RemoveMetricValue(base::StringPiece histogram_name);

 private:
  void StartScheduledUpload(bool is_star, MetricLogType log_type);
  void StartScheduledStarPrep();

  MetricLogType GetLogTypeForHistogram(const std::string& histogram_name);

  void OnLogUploadComplete(bool is_ok,
                           int response_code,
                           bool is_star,
                           MetricLogType log_type);

  void OnNewStarMessage(std::string histogram_name,
                        uint8_t epoch,
                        std::unique_ptr<std::string> serialized_message);

  void OnRandomnessServerInfoReady(RandomnessServerInfo* server_info);

  // Restart the uploading process (i.e. mark all values as unsent).
  void DoJsonRotation(MetricLogType log_type);

  void DoStarRotation();

  // BraveP3AMetricLogStore::Delegate
  std::string SerializeLog(base::StringPiece histogram_name,
                           const uint64_t value,
                           MetricLogType log_type,
                           bool is_star,
                           const std::string& upload_type) override;
  bool IsActualMetric(const std::string& histogram_name) const override;
  bool IsEphemeralMetric(const std::string& histogram_name) const override;

  PrefService* local_state_ = nullptr;

  MessageMetainfo message_meta_;

  BraveP3AConfig* config_;

  base::flat_map<MetricLogType, std::unique_ptr<BraveP3AMetricLogStore>>
      json_log_stores_;
  std::unique_ptr<BraveP3AMetricLogStore> star_prep_log_store_;
  std::unique_ptr<BraveP3AStarLogStore> star_send_log_store_;

  std::unique_ptr<BraveP3AUploader> uploader_;
  base::flat_map<MetricLogType, std::unique_ptr<BraveP3AScheduler>>
      json_upload_schedulers_;
  std::unique_ptr<BraveP3AScheduler> star_prep_scheduler_;
  std::unique_ptr<BraveP3AScheduler> star_upload_scheduler_;

  std::unique_ptr<BraveP3AStar> star_manager_;

  std::unique_ptr<BraveP3ARotationScheduler> rotation_scheduler_;

  Delegate* const delegate_ = nullptr;
};

}  // namespace brave

#endif  // BRAVE_COMPONENTS_P3A_BRAVE_P3A_MESSAGE_MANAGER_H_
