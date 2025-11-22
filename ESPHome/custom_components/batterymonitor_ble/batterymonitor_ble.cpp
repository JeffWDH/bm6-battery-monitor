#include "batterymonitor_ble.h"
#include "esphome/core/log.h"
#include <cinttypes>

#ifdef USE_ESP32

namespace esphome {
namespace batterymonitor_ble {

static const char *const TAG = "batterymonitor_ble";

// Battery Monitor (BM2) sensor details
static const uint16_t SERVICE_UUID_BM2 = 0xFFF1;
static const uint16_t MANUFACTURER_BM2_ID = 0x000D;  // 
static const uint8_t MANUFACTURER_BM2_DATA_LENGTH = 23;

// Battery Monitor (BM6) sensor details
static const uint16_t SERVICE_UUID_BM6 = 0xFFF0;
static const uint16_t MANUFACTURER_BM6_ID = 0x75BF;  // 
static const uint8_t MANUFACTURER_BM6_DATA_LENGTH = 14;

/**
 * Parse all incoming BLE payloads to see if it is a Battery Monitor BLE advertisement.
 * Currently this supports the following products:
 *
 *  - BM2
 *  - BM6
 *
 *    It report the MAC so a user can add this as a sensor.
 * Three points are used to identify a sensor:
 *
 * - Bluetooth service uuid
 * - Bluetooth manufacturer id
 * - Bluetooth data frame size
 */
bool BatteryMonitorListener::parse_device(const esp32_ble_tracker::ESPBTDevice &device) {
  // Fetch information about BLE device.
  const auto &service_uuids = device.get_service_uuids();
  if (service_uuids.size() != 1) {
    return false;
  }
  const auto &service_uuid = service_uuids[0];

  const auto &manu_datas = device.get_manufacturer_datas();
  if (manu_datas.size() != 1) {
    return false;
  }
  const auto &manu_data = manu_datas[0];

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
