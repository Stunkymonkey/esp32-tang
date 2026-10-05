import esphome.codegen as cg
from esphome.components import button, text
import esphome.config_validation as cv

from . import CONF_TANG_SERVER_ID, TangServer, check_activate_password, tang_server_ns

DEPENDENCIES = ["tang_server"]

CONF_DEACTIVATE = "deactivate"
CONF_WIPE = "wipe"
CONF_ACTIVATE = "activate"
CONF_PASSWORD_ID = "password_id"

DeactivateButton = tang_server_ns.class_("DeactivateButton", button.Button)
WipeButton = tang_server_ns.class_("WipeButton", button.Button)
ActivateButton = tang_server_ns.class_("ActivateButton", button.Button)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_TANG_SERVER_ID): cv.use_id(TangServer),
        cv.Optional(CONF_DEACTIVATE): button.button_schema(DeactivateButton, icon="mdi:lock"),
        cv.Optional(CONF_WIPE): button.button_schema(WipeButton, icon="mdi:delete-forever"),
        # nvs only. With require_password, password_id names a text entity,
        # which is read and then cleared on every press.
        cv.Optional(CONF_ACTIVATE): button.button_schema(
            ActivateButton, icon="mdi:lock-open-variant"
        ).extend({cv.Optional(CONF_PASSWORD_ID): cv.use_id(text.Text)}),
    }
)


async def to_code(config):
    server = await cg.get_variable(config[CONF_TANG_SERVER_ID])
    for key in (CONF_DEACTIVATE, CONF_WIPE, CONF_ACTIVATE):
        if (conf := config.get(key)) is None:
            continue
        if key == CONF_ACTIVATE:
            check_activate_password(
                CONF_PASSWORD_ID in conf, "the tang_server activate button", "a password_id"
            )
        var = await button.new_button(conf)
        cg.add(var.set_parent(server))
        if CONF_PASSWORD_ID in conf:
            cg.add(var.set_password_text(await cg.get_variable(conf[CONF_PASSWORD_ID])))
