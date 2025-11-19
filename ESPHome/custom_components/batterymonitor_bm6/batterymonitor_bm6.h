#pragma once

#ifndef USE_ESP32
#define USE_ESP32 
#endif

#ifdef USE_ESP32

#include <esp_gattc_api.h>
#include <algorithm>
#include <iterator>
#include "esphome/components/ble_client/ble_client.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/core/component.h"
#include "esphome/core/log.h"

namespace esphome {
namespace batterymonitor_bm6 {

static const char *const SERVICE_UUID = "0000fff0-0000-1000-8000-00805f9b34fb";
static const char *const WRITE_CHARACTERISTIC_UUID = "0000fff3-0000-1000-8000-00805f9b34fb";
static const char *const READ_CHARACTERISTIC_UUID = "0000fff4-0000-1000-8000-00805f9b34fb";

class BatteryMonitor_BM6 : public PollingComponent, public ble_client::BLEClientNode {
 public:
  BatteryMonitor_BM6();

  void dump_config() override;
  void update() override;

  void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                           esp_ble_gattc_cb_param_t *param) override;

  void set_battery_voltage(sensor::Sensor *voltage) { battery_voltage_ = voltage; }
  void set_temperature_sensor(sensor::Sensor *temperature_sensor) { temperature_sensor_ = temperature_sensor; }
  void set_battery_level(sensor::Sensor *bat) { battery_level_ = bat; };

  void set_encryption_key(const std::vector<uint8_t> &encryption_key) { this->encryption_key_ = encryption_key; }
  void set_disconnect_delay(uint32_t ms) { this->disconnect_delay_ms_ = ms; }

 private:
  bool decrypt(const uint8_t *ecb_ciphertext, uint8_t *ecb_plaintext);
  bool encrypt(const uint8_t *ecb_plaintext, uint8_t *ecb_ciphertext);

 protected:
  void read_sensors_(uint8_t *value, uint16_t value_len);
  void write_query_message_();
  void request_read_values_();
  void delayed_disconnect_();

  sensor::Sensor *battery_voltage_{nullptr};
  sensor::Sensor *temperature_sensor_{nullptr};
  sensor::Sensor *battery_level_{nullptr};

  std::vector<uint8_t> encryption_key_;
  uint32_t disconnect_delay_ms_ = 5000;

  uint16_t read_handle_;
  uint16_t write_handle_;
  esp32_ble_tracker::ESPBTUUID service_uuid_;
  esp32_ble_tracker::ESPBTUUID sensors_write_characteristic_uuid_;
  esp32_ble_tracker::ESPBTUUID sensors_read_characteristic_uuid_;
};

}  // namespace batterymonitor_bm6
}  // namespace esphome

#endif  // USE_ESP32
