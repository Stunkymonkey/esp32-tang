import esphome.codegen as cg
from esphome.components import sensor
import esphome.config_validation as cv
from esphome.const import STATE_CLASS_TOTAL_INCREASING

from . import CONF_TANG_SERVER_ID, TangServer

DEPENDENCIES = ["tang_server"]

# Counters since boot. total_increasing, so Home Assistant handles the reset
# at every boot.
SENSORS = {
    "activation_count": ("set_activation_count_sensor", "mdi:lock-open-variant"),
    "recovery_count": ("set_recovery_count_sensor", "mdi:key-arrow-right"),
    "adv_count": ("set_adv_count_sensor", "mdi:bullhorn"),
    "auth_failure_count": ("set_auth_failure_count_sensor", "mdi:shield-alert"),
}

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_TANG_SERVER_ID): cv.use_id(TangServer),
        **{
            cv.Optional(key): sensor.sensor_schema(
                icon=icon,
                accuracy_decimals=0,
                state_class=STATE_CLASS_TOTAL_INCREASING,
            )
            for key, (_, icon) in SENSORS.items()
        },
    }
)


async def to_code(config):
    server = await cg.get_variable(config[CONF_TANG_SERVER_ID])
    for key, (setter, _) in SENSORS.items():
        if conf := config.get(key):
            sens = await sensor.new_sensor(conf)
            cg.add(getattr(server, setter)(sens))
