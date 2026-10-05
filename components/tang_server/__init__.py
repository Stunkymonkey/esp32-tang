import esphome.codegen as cg
from esphome.components import esp32, web_server_base
from esphome.components.web_server_base import CONF_WEB_SERVER_BASE_ID
import esphome.config_validation as cv
from esphome.const import CONF_ID

CODEOWNERS = ["@Stunkymonkey"]
DEPENDENCIES = ["network"]
AUTO_LOAD = ["web_server_base", "json"]

CONF_KEY_STORAGE = "key_storage"
CONF_REQUIRE_PASSWORD = "require_password"
CONF_PBKDF2_ITERATIONS = "pbkdf2_iterations"
CONF_ADMIN_TOKEN = "admin_token"
CONF_MAX_ACTIVE_TIME = "max_active_time"
CONF_IDLE_TIMEOUT = "idle_timeout"
CONF_AUTH_BACKOFF = "auth_backoff"
CONF_MAX_FAILURES = "max_failures"
CONF_LOCKOUT = "lockout"

TRIGGERS = [
    "on_activate",
    "on_deactivate",
    "on_state_change",
    "on_recovery",
    "on_adv",
    "on_request",
    "on_auth_failure",
    "on_rejected",
]

tang_server_ns = cg.esphome_ns.namespace("tang_server")
TangServer = tang_server_ns.class_("TangServer", cg.Component)
KeyStorage = tang_server_ns.enum("KeyStorage", is_class=True)

KEY_STORAGES = {
    "ram": KeyStorage.RAM,
    "nvs": KeyStorage.NVS,
}

# Options that validate already but are built in later steps of
# docs/esphome-implementation.md.
NOT_IMPLEMENTED = [
    CONF_REQUIRE_PASSWORD,
    CONF_PBKDF2_ITERATIONS,
    CONF_MAX_ACTIVE_TIME,
    CONF_IDLE_TIMEOUT,
    CONF_AUTH_BACKOFF,
    *TRIGGERS,
]


def _validate(config):
    if config.get(CONF_REQUIRE_PASSWORD) and config[CONF_KEY_STORAGE] != "nvs":
        raise cv.Invalid(
            f"{CONF_REQUIRE_PASSWORD} needs {CONF_KEY_STORAGE}: nvs",
            path=[CONF_REQUIRE_PASSWORD],
        )
    if CONF_PBKDF2_ITERATIONS in config and not config.get(CONF_REQUIRE_PASSWORD):
        raise cv.Invalid(
            f"{CONF_PBKDF2_ITERATIONS} needs {CONF_REQUIRE_PASSWORD}: true",
            path=[CONF_PBKDF2_ITERATIONS],
        )

    if config[CONF_KEY_STORAGE] != "ram":
        raise cv.Invalid(
            f"{CONF_KEY_STORAGE}: {config[CONF_KEY_STORAGE]} is not implemented yet",
            path=[CONF_KEY_STORAGE],
        )
    for key in NOT_IMPLEMENTED:
        if key in config:
            raise cv.Invalid(f"{key} is not implemented yet", path=[key])
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(TangServer),
            cv.GenerateID(CONF_WEB_SERVER_BASE_ID): cv.use_id(
                web_server_base.WebServerBase
            ),
            cv.Required(CONF_KEY_STORAGE): cv.one_of(*KEY_STORAGES, lower=True),
            cv.Optional(CONF_REQUIRE_PASSWORD): cv.boolean,
            cv.Optional(CONF_PBKDF2_ITERATIONS): cv.int_range(min=1),
            cv.Optional(CONF_ADMIN_TOKEN): cv.All(cv.string_strict, cv.Length(min=1)),
            cv.Optional(CONF_MAX_ACTIVE_TIME): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_IDLE_TIMEOUT): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_AUTH_BACKOFF): cv.Schema(
                {
                    cv.Optional(CONF_MAX_FAILURES, default=5): cv.int_range(min=1),
                    cv.Optional(
                        CONF_LOCKOUT, default="5min"
                    ): cv.positive_time_period_milliseconds,
                }
            ),
            **{cv.Optional(trigger): cv.valid for trigger in TRIGGERS},
        }
    ).extend(cv.COMPONENT_SCHEMA),
    cv.only_on_esp32,
    _validate,
)


async def to_code(config):
    base = await cg.get_variable(config[CONF_WEB_SERVER_BASE_ID])
    var = cg.new_Pvariable(config[CONF_ID], base)
    await cg.register_component(var, config)

    cg.add(var.set_key_storage(KEY_STORAGES[config[CONF_KEY_STORAGE]]))
    if CONF_ADMIN_TOKEN in config:
        cg.add(var.set_admin_token(config[CONF_ADMIN_TOKEN]))

    # ES512 signatures for P-521 and the S384/S512 thumbprints. ESPHome turns
    # SHA-384/512 off on ESP-IDF 6 unless a component asks for them.
    esp32.require_mbedtls_sha512()
