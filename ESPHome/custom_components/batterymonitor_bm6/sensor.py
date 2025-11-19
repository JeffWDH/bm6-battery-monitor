from esphome import automation
from esphome.automation import maybe_simple_id
import esphome.codegen as cg
from esphome.components import ble_client, sensor
import esphome.config_validation as cv
from esphome.const import (
    CONF_ID,
    CONF_DISCONNECT_DELAY,
    CONF_TEMPERATURE,
    CONF_BATTERY_VOLTAGE,
    CONF_BATTERY_LEVEL,
    DEVICE_CLASS_BATTERY,
    DEVICE_CLASS_VOLTAGE,
    DEVICE_CLASS_TEMPERATURE,
    ICON_FLASH,
    ICON_PERCENT,
    STATE_CLASS_MEASUREMENT,
    ENTITY_CATEGORY_DIAGNOSTIC,
    UNIT_CELSIUS,
    UNIT_VOLT,
    UNIT_PERCENT,
)

CONF_ENCRYPTION_KEY = "encryption_key"
ICON_CAR_BATTERY = "mdi:car-battery"

DEPENDENCIES = ["ble_client"]

batterymonitor_bm6_ns = cg.esphome_ns.namespace("batterymonitor_bm6")
BatteryMonitor_BM6 = batterymonitor_bm6_ns.class_(
    "BatteryMonitor_BM6", cg.PollingComponent, ble_client.BLEClientNode
)

BMConnectAction = batterymonitor_bm6_ns.class_("BMConnectAction", automation.Action)


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(BatteryMonitor_BM6),
            cv.Required(CONF_ENCRYPTION_KEY): cv.ensure_list(cv.uint8_t), # TODO: validate length
            cv.Optional(CONF_DISCONNECT_DELAY, default="15s"): cv.positive_time_period,
            cv.Optional(CONF_BATTERY_VOLTAGE): sensor.sensor_schema(
                unit_of_measurement=UNIT_VOLT,
                icon=ICON_FLASH,
                accuracy_decimals=2,
                device_class=DEVICE_CLASS_VOLTAGE,
                state_class=STATE_CLASS_MEASUREMENT,
#                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            cv.Optional(CONF_TEMPERATURE): sensor.sensor_schema(
                unit_of_measurement=UNIT_CELSIUS,
                icon=ICON_CAR_BATTERY,
                accuracy_decimals=0,
                device_class=DEVICE_CLASS_TEMPERATURE,
                state_class=STATE_CLASS_MEASUREMENT,
            ),
            cv.Optional(CONF_BATTERY_LEVEL): sensor.sensor_schema(
                unit_of_measurement=UNIT_PERCENT,
                icon=ICON_PERCENT,
                accuracy_decimals=0,
                device_class=DEVICE_CLASS_BATTERY,
                state_class=STATE_CLASS_MEASUREMENT,
            ),
        }
    )
    .extend(cv.polling_component_schema("30min"))
    .extend(ble_client.BLE_CLIENT_SCHEMA),
)

BM6_CONNECT_ACTION_SCHEMA = maybe_simple_id(
    {
        cv.GenerateID(CONF_ID): cv.use_id(BatteryMonitor_BM6),
    }
)

async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    await ble_client.register_ble_node(var, config)

    cg.add(var.set_encryption_key(config[CONF_ENCRYPTION_KEY]))
    cg.add(var.set_disconnect_delay(config[CONF_DISCONNECT_DELAY].total_milliseconds))

    if config_battery_voltage := config.get(CONF_BATTERY_VOLTAGE):
        sens = await sensor.new_sensor(config_battery_voltage)
        cg.add(var.set_battery_voltage(sens))

    if config_temperature := config.get(CONF_TEMPERATURE):
        sens = await sensor.new_sensor(config_temperature)
        cg.add(var.set_temperature_sensor(sens))

    if config_battery_level := config.get(CONF_BATTERY_LEVEL):
        sens = await sensor.new_sensor(config_battery_level)
        cg.add(var.set_battery_level(sens))

@automation.register_action(
    "batterymonitor_bm6.connect", BMConnectAction, BM6_CONNECT_ACTION_SCHEMA
)
async def batterymonitor_bm6_connect_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    return var
