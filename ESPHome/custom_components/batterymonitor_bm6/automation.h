#pragma once

#include "esphome/core/component.h"
#include "esphome/core/automation.h"

#include "batterymonitor_bm6.h"

namespace esphome {
namespace batterymonitor_bm6 {
/*
template<typename... Ts> class BMConnectAction : public Action<Ts...>, public Parented<BatteryMonitor_BM6> {
 public:
  void play(Ts... x) override { this->parent_->update(); }
};
*/
template<typename... Ts> class BMConnectAction : public Action<Ts...> {
 public:
  explicit BMConnectAction(BatteryMonitor_BM6 *bm6) : bm6_(bm6) {}

  void play(Ts... x) override {
    this->bm6_->update();
  }

 protected:
  BatteryMonitor_BM6 *bm6_;
};
}  // namespace batterymonitor_bm6
}  // namespace esphome
