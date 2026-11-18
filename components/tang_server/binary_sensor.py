import esphome.codegen as cg
from esphome.components import binary_sensor
import esphome.config_validation as cv

from . import CONF_TANG_SERVER_ID, TangServer

DEPENDENCIES = ["tang_server"]

CONF_ACTIVE = "active"

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_TANG_SERVER_ID): cv.use_id(TangServer),
        # On while /adv and /rec are served.
        cv.Optional(CONF_ACTIVE): binary_sensor.binary_sensor_schema(icon="mdi:key"),
    }
)


async def to_code(config):
    server = await cg.get_variable(config[CONF_TANG_SERVER_ID])
    if conf := config.get(CONF_ACTIVE):
        sens = await binary_sensor.new_binary_sensor(conf)
        cg.add(server.set_active_binary_sensor(sens))
