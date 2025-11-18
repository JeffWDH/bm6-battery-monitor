#include "batterymonitor_ble.h"
#include "esphome/core/log.h"
#include <cinttypes>

#ifdef USE_ESP32

namespace esphome {
namespace batterymonitor_ble {

static const char *const TAG = "batterymonitor_ble";

// Mopeka Std (BM2) sensor details
static const uint16_t SERVICE_UUID_BM2 = 0xFFF1;
static const uint16_t MANUFACTURER_BM2_ID = 0x000D;  // 
static const uint8_t MANUFACTURER_BM2_DATA_LENGTH = 23;

// Mopeka Pro (BM6) sensor details
static const uint16_t SERVICE_UUID_BM6 = 0xFFF0;
static const uint16_t MANUFACTURER_BM6_ID = 0x75BF;  // 
static const uint8_t MANUFACTURER_BM6_DATA_LENGTH = 14;

bool BatteryMonitorListener::parse_device(const esp32_ble_tracker::ESPBTDevice &device) {
  // Fetch information about BLE device.
  ESP_LOGI(TAG, "BatteryMonitorListener::parse_device called");
  const auto &service_uuids = device.get_service_uuids();
  if (service_uuids.size() != 1) {
  ESP_LOGI(TAG, "service uid != 1");
    return false;
  }
  const auto &service_uuid = service_uuids[0];

  const auto &manu_datas = device.get_manufacturer_datas();
  if (manu_datas.size() != 1) {
    ESP_LOGI(TAG, "manu_datas.size() != 1");
    return false;
  }
  const auto &manu_data = manu_datas[0];

  ESP_LOGD(TAG, "Read data: %s, %s", manu_data.uuid.to_string().c_str(), format_hex_pretty(manu_data.data).c_str());

  // Is the device maybe a BM2 sensor.
  if (service_uuid == esp32_ble_tracker::ESPBTUUID::from_uint16(SERVICE_UUID_BM2)) {
    if (manu_data.uuid != esp32_ble_tracker::ESPBTUUID::from_uint16(MANUFACTURER_BM2_ID)) {
      return false;
    }

    if (manu_data.data.size() != MANUFACTURER_BM2_DATA_LENGTH) {
      return false;
    }

//    const bool sync_button_pressed = (manu_data.data[3] & 0x80) != 0;

//    if (this->show_sensors_without_sync_ || sync_button_pressed) {
      ESP_LOGI(TAG, "BM2 BATTERY MONITOR FOUND: %s", device.address_str().c_str());
//    }

    // Is the device maybe a BM6 sensor.
  } else if (service_uuid == esp32_ble_tracker::ESPBTUUID::from_uint16(SERVICE_UUID_BM6)) {
    if (manu_data.uuid != esp32_ble_tracker::ESPBTUUID::from_uint16(MANUFACTURER_BM6_ID)) {
      return false;
    }

    if (manu_data.data.size() != MANUFACTURER_BM6_DATA_LENGTH) {
      return false;
    }

//    const bool sync_button_pressed = (manu_data.data[2] & 0x80) != 0;

//    if (this->show_sensors_without_sync_ || sync_button_pressed) {
      ESP_LOGI(TAG, "BM6 BATTERY MONITOR FOUND: %s", device.address_str().c_str());
//    }
  }

  return false;
}

}  // namespace batterymonitor_ble
}  // namespace esphome

#endif
