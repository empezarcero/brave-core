/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_VENDOR_BAT_NATIVE_ADS_SRC_BAT_ADS_INTERNAL_ADS_SERVING_ELIGIBLE_ADS_ALLOCATION_ROUND_ROBIN_ADS_H_
#define BRAVE_VENDOR_BAT_NATIVE_ADS_SRC_BAT_ADS_INTERNAL_ADS_SERVING_ELIGIBLE_ADS_ALLOCATION_ROUND_ROBIN_ADS_H_

#include <algorithm>
#include <iterator>
#include <map>
#include <string>

namespace ads {

struct CreativeAdInfo;

template <typename T>
T FilterSeenAds(const T& ads, const std::map<std::string, bool>& seen_ads) {
  T unseen_ads;

  std::copy_if(ads.cbegin(), ads.cend(), std::back_inserter(unseen_ads),
               [&seen_ads](const CreativeAdInfo& creative_ad) {
                 return seen_ads.find(creative_ad.creative_instance_id) ==
                        seen_ads.cend();
               });

  return unseen_ads;
}

}  // namespace ads

#endif  // BRAVE_VENDOR_BAT_NATIVE_ADS_SRC_BAT_ADS_INTERNAL_ADS_SERVING_ELIGIBLE_ADS_ALLOCATION_ROUND_ROBIN_ADS_H_
