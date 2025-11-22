#include "batterymonitor_bm6.h"

#define MBEDTLS_AES_ALT
#include <aes_alt.h>

#ifdef USE_ESP32

namespace esphome {
namespace batterymonitor_bm6 {

static const char *const TAG = "batterymonitor_bm6";

void BatteryMonitor_BM6::gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                                        esp_ble_gattc_cb_param_t *param) {
  switch (event) {
    case ESP_GATTC_OPEN_EVT: {
      if (param->open.status == ESP_GATT_OK) {
        ESP_LOGI(TAG, "Connected successfully!");
        this->delayed_disconnect_();
      }
      break;
    }

    case ESP_GATTC_DISCONNECT_EVT: {
      ESP_LOGW(TAG, "Disconnected!");
      break;
    }

    case ESP_GATTC_SEARCH_CMPL_EVT: {
      this->read_handle_ = 0;
      auto *chr = this->parent()->get_characteristic(service_uuid_, sensors_read_characteristic_uuid_);
      if (chr == nullptr) {
        this->status_set_warning();
        ESP_LOGW(TAG, "No sensor read characteristic found at service %s char %s", service_uuid_.to_string().c_str(),
                 sensors_read_characteristic_uuid_.to_string().c_str());
        break;
      }
      this->read_handle_ = chr->handle;

      // Write a query message to the write characteristic.
      auto *write_chr = this->parent()->get_characteristic(service_uuid_, sensors_write_characteristic_uuid_);
      if (write_chr == nullptr) {
        ESP_LOGW(TAG, "No control service found at device at service %s char %s", service_uuid_.to_string().c_str(),
                 sensors_read_characteristic_uuid_.to_string().c_str());
        break;
      }
      this->write_handle_ = write_chr->handle;

      auto status = esp_ble_gattc_register_for_notify(this->parent_->get_gattc_if(), this->parent_->get_remote_bda(),
                                                      chr->handle);
      if (status) {
        ESP_LOGW(TAG, "esp_ble_gattc_register_for_notify failed, status=%d", status);
      }
      break;
    }

    case ESP_GATTC_REG_FOR_NOTIFY_EVT: {
      if (param->reg_for_notify.handle == this->read_handle_) {
        if (param->reg_for_notify.status != ESP_GATT_OK) {
          ESP_LOGW(TAG, "Error registering for notifications at handle %d, status=%d", param->reg_for_notify.handle,
                   param->reg_for_notify.status);
          break;
        }
        this->node_state = esp32_ble_tracker::ClientState::ESTABLISHED;
        ESP_LOGD(TAG, "Register for notify on %s complete", this->sensors_read_characteristic_uuid_.to_string().c_str());
        this->write_query_message_();
        this->delayed_disconnect_();
      }
      break;
    }
    case ESP_GATTC_NOTIFY_EVT: {
      if (param->notify.conn_id != this->parent()->get_conn_id()) {
        ESP_LOGW(TAG, "not my connection: %d, %d", param->notify.conn_id,  this->parent()->get_conn_id());
        break;
      }
      if (param->notify.handle != this->read_handle_) {
        ESP_LOGW(TAG, "not my handle: %d, w: %d, r:%d", param->notify.handle,  this->write_handle_, this->read_handle_);
        break;
      }
      this->read_sensors_(param->notify.value, param->notify.value_len);
      break;
    }

    default:
      break;
  }
}

void BatteryMonitor_BM6::read_sensors_(uint8_t *value, uint16_t value_len) {

  ESP_LOGI(TAG, "result bytes [%d]: %s", value_len, format_hex(value, value_len).c_str());
  if (value_len != 16) {
    ESP_LOGW(TAG, "Invalid read: need 16, got %d", value_len);
    return;
  }
  uint8_t data[16];
  if (!this->decrypt(value, data)) {
    ESP_LOGW(TAG, "Failed to decrypt data: %s", format_hex(value, value_len).c_str());
    return;
  }
  ESP_LOGI(TAG, "data bytes: %s", format_hex(data, value_len).c_str());

  // FIXME: d15507 header check?
  if (data[3] == 0xff) {
    // d15507ff000000000000000000000000
    ESP_LOGD(TAG, "Invalid state, skip");
    return;
  }
  int tempC;
  if (data[3] == 1) {
    tempC = -data[4];
  } else {
    tempC = data[4];
  }
  float socp = data[6] *1.0f;
  float volts = ((data[7] << 8) | data[8]) / 100.0f;

  ESP_LOGD(TAG, "temperature: %d, volts: %0.03f, socp: %0.03f", tempC, volts, socp);

  if (volts > 0) {
    if (this->temperature_sensor_ != nullptr) {
      this->temperature_sensor_->publish_state(tempC);
    }
    if (this->battery_voltage_ != nullptr) {
      this->battery_voltage_->publish_state(volts);
    }
    if (this->battery_level_ != nullptr) {
      this->battery_level_->publish_state(socp);
    }
  }

  // This instance must not stay connected
  // so other clients can connect to it (e.g. the
  // mobile app).
  parent()->set_enabled(false);
}

void BatteryMonitor_BM6::update() {
  ESP_LOGD(TAG, "parent()->enabled: %d", parent()->enabled);
  if (this->node_state != esp32_ble_tracker::ClientState::ESTABLISHED) {
    if (!parent()->enabled) {
      ESP_LOGW(TAG, "Reconnecting to device");
      parent()->set_enabled(true);
      parent()->connect();
    } else {
      ESP_LOGW(TAG, "Connection in progress");
    }
  }
}

bool BatteryMonitor_BM6::decrypt(const uint8_t *ecb_ciphertext, uint8_t *ecb_plaintext) {
  uint8_t ecb_key[16];
  memcpy(&ecb_key, this->encryption_key_.data(), 16);

  mbedtls_aes_context ctx = {0, 0, {0}};
  mbedtls_aes_init(&ctx);

  if (mbedtls_aes_setkey_dec(&ctx, ecb_key, 128) != 0) {
    mbedtls_aes_free(&ctx);
    return false;
  }

  if (mbedtls_aes_crypt_ecb(&ctx, ESP_AES_DECRYPT, ecb_ciphertext, ecb_plaintext) != 0) {
    mbedtls_aes_free(&ctx);
    return false;
  }

  mbedtls_aes_free(&ctx);
  return true;
}

bool BatteryMonitor_BM6::encrypt(const uint8_t *ecb_plaintext, uint8_t *ecb_ciphertext) {
  uint8_t ecb_key[16];
  memcpy(&ecb_key, this->encryption_key_.data(), 16);

  mbedtls_aes_context ctx = {0, 0, {0}};
  mbedtls_aes_init(&ctx);

  if (mbedtls_aes_setkey_enc(&ctx, ecb_key, 128) != 0) {
    mbedtls_aes_free(&ctx);
    return false;
  }

  if (mbedtls_aes_crypt_ecb(&ctx, ESP_AES_ENCRYPT, ecb_plaintext, ecb_ciphertext) != 0) {
    mbedtls_aes_free(&ctx);
    return false;
  }

  mbedtls_aes_free(&ctx);
  return true;
}

void BatteryMonitor_BM6::write_query_message_() {
  ESP_LOGV(TAG, "writing query message to write service");
//  uint8_t request[16] =  {0x69, 0x7e, 0xa0, 0xb5, 0xd5, 0x4c, 0xf0, 0x24, 0xe7, 0x94, 0x77, 0x23, 0x55, 0x55, 0x41, 0x14}; // Encrypted "d1550700000000000000000000000000"
  uint8_t data[16] = { 0xd1, 0x55, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // "d1550700000000000000000000000000"
  uint8_t request[16];
  this->encrypt(data, request);
  ESP_LOGD(TAG, "request: %s", format_hex(&request[0], 16).c_str());
  
  auto status = esp_ble_gattc_write_char_descr(this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
                                               this->write_handle_, sizeof(request), request,
                                               ESP_GATT_WRITE_TYPE_NO_RSP, ESP_GATT_AUTH_REQ_NONE);
  if (status) {
    ESP_LOGW(TAG, "Error sending write request for sensor, status=%d", status);
  }
}

void BatteryMonitor_BM6::request_read_values_() {
  auto status = esp_ble_gattc_read_char(this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
                                        this->read_handle_, ESP_GATT_AUTH_REQ_NONE);
  if (status) {
    ESP_LOGW(TAG, "Error sending read request for sensor, status=%d", status);
  }
}

void BatteryMonitor_BM6::delayed_disconnect_() {
  if (this->disconnect_delay_ms_ == 0)
    return;
  this->cancel_timeout("disconnect");
  this->set_timeout("disconnect", this->disconnect_delay_ms_, [this]() { this->parent_->set_enabled(false); });
}


void BatteryMonitor_BM6::dump_config() {
  ESP_LOGCONFIG(TAG, "Battery Monitor BM6:");
  ESP_LOGCONFIG(TAG, "  MAC address                : %s", this->parent_->address_str().c_str());
  ESP_LOGCONFIG(TAG, "  Service UUID               : %s", this->service_uuid_.to_string().c_str());
  ESP_LOGCONFIG(TAG, "  Write characteristic UUID  : %s", this->sensors_write_characteristic_uuid_.to_string().c_str());
  ESP_LOGCONFIG(TAG, "  Notify characteristic UUID : %s", this->sensors_read_characteristic_uuid_.to_string().c_str());
  ESP_LOGCONFIG(TAG, "  Disconnect delay           : %" PRIu32 "ms", this->disconnect_delay_ms_);
  LOG_SENSOR("  ", "BM6 Battery temperature", this->temperature_sensor_);
  LOG_SENSOR("  ", "BM6 Battery voltate", this->battery_voltage_);
  LOG_SENSOR("  ", "BM6 Battery level", this->battery_level_);
  LOG_UPDATE_INTERVAL(this);
}

BatteryMonitor_BM6::BatteryMonitor_BM6()
    : PollingComponent(10000),
      service_uuid_(esp32_ble_tracker::ESPBTUUID::from_raw(SERVICE_UUID)),
      sensors_write_characteristic_uuid_(esp32_ble_tracker::ESPBTUUID::from_raw(WRITE_CHARACTERISTIC_UUID)),
      sensors_read_characteristic_uuid_(esp32_ble_tracker::ESPBTUUID::from_raw(READ_CHARACTERISTIC_UUID)) {}

}  // namespace batterymonitor_bm6
}  // namespace esphome

#endif  // USE_ESP32
