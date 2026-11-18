import esphome.codegen as cg
from esphome.components import text_sensor
import esphome.config_validation as cv
from esphome.const import ENTITY_CATEGORY_DIAGNOSTIC

from . import CONF_TANG_SERVER_ID, TangServer

DEPENDENCIES = ["tang_server"]

TEXT_SENSORS = {
    # unprovisioned, pending, locked or active
    "state": ("set_state_text_sensor", "mdi:lock", None),
    # the last request the component handled
    "last_path": ("set_last_path_text_sensor", "mdi:web", None),
    # a short, safe message, never key material or a password
    "last_error": ("set_last_error_text_sensor", "mdi:alert-circle", ENTITY_CATEGORY_DIAGNOSTIC),
    "last_client_ip": ("set_last_client_ip_text_sensor", "mdi:ip-network", ENTITY_CATEGORY_DIAGNOSTIC),
}

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_TANG_SERVER_ID): cv.use_id(TangServer),
        **{
            cv.Optional(key): text_sensor.text_sensor_schema(
                icon=icon, **({"entity_category": category} if category else {})
            )
            for key, (_, icon, category) in TEXT_SENSORS.items()
        },
    }
)


async def to_code(config):
    server = await cg.get_variable(config[CONF_TANG_SERVER_ID])
    for key, (setter, _, _) in TEXT_SENSORS.items():
        if conf := config.get(key):
            sens = await text_sensor.new_text_sensor(conf)
            cg.add(getattr(server, setter)(sens))
