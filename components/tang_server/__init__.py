from esphome import automation
import esphome.codegen as cg
from esphome.components import esp32, web_server_base
from esphome.components.web_server_base import CONF_WEB_SERVER_BASE_ID
import esphome.config_validation as cv
from esphome.const import CONF_ID, CONF_PASSWORD, CONF_TRIGGER_ID
from esphome.core import CORE, EsphomeError

CODEOWNERS = ["@Stunkymonkey"]
DEPENDENCIES = ["network"]
AUTO_LOAD = ["web_server_base", "json"]

CONF_TANG_SERVER_ID = "tang_server_id"
CONF_KEY_STORAGE = "key_storage"
CONF_REQUIRE_PASSWORD = "require_password"
CONF_PBKDF2_ITERATIONS = "pbkdf2_iterations"
CONF_ADMIN_TOKEN = "admin_token"
CONF_MAX_ACTIVE_TIME = "max_active_time"
CONF_IDLE_TIMEOUT = "idle_timeout"
CONF_AUTH_BACKOFF = "auth_backoff"
CONF_MAX_FAILURES = "max_failures"
CONF_LOCKOUT = "lockout"

DEFAULT_PBKDF2_ITERATIONS = 20000

tang_server_ns = cg.esphome_ns.namespace("tang_server")
TangServer = tang_server_ns.class_("TangServer", cg.Component)
KeyStorage = tang_server_ns.enum("KeyStorage", is_class=True)

# Trigger: (C++ class, its variables). They run on the main loop.
TRIGGERS = {
    "on_activate": ("ActivateTrigger", [(cg.bool_, "success")]),
    "on_deactivate": ("DeactivateTrigger", [(cg.std_string, "reason")]),
    "on_state_change": ("StateChangeTrigger", [(cg.std_string, "state")]),
    "on_recovery": ("RecoveryTrigger", [(cg.std_string, "thp"), (cg.bool_, "success")]),
    "on_adv": ("AdvTrigger", [(cg.std_string, "thp")]),
    "on_request": (
        "RequestTrigger",
        [(cg.std_string, "path"), (cg.std_string, "method"), (cg.int_, "status")],
    ),
    "on_auth_failure": ("AuthFailureTrigger", [(cg.std_string, "path")]),
    "on_rejected": (
        "RejectedTrigger",
        [(cg.std_string, "path"), (cg.std_string, "reason")],
    ),
}
TRIGGER_CLASSES = {
    name: tang_server_ns.class_(cls, automation.Trigger.template(*(t for t, _ in args)))
    for name, (cls, args) in TRIGGERS.items()
}

ActivateAction = tang_server_ns.class_("ActivateAction", automation.Action)
DeactivateAction = tang_server_ns.class_("DeactivateAction", automation.Action)
WipeAction = tang_server_ns.class_("WipeAction", automation.Action)
IsActiveCondition = tang_server_ns.class_("IsActiveCondition", automation.Condition)
IsLockedCondition = tang_server_ns.class_("IsLockedCondition", automation.Condition)
IsProvisionedCondition = tang_server_ns.class_(
    "IsProvisionedCondition", automation.Condition
)

KEY_STORAGES = {
    "ram": KeyStorage.RAM,
    "nvs": KeyStorage.NVS,
}

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
            cv.Optional(CONF_PBKDF2_ITERATIONS): cv.int_range(min=1, max=10000000),
            # Redacted in `esphome config` output and masked by frontends.
            cv.Optional(CONF_ADMIN_TOKEN): cv.sensitive(
                cv.All(cv.string_strict, cv.Length(min=1))
            ),
            cv.Optional(CONF_MAX_ACTIVE_TIME): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_IDLE_TIMEOUT): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_AUTH_BACKOFF, default={}): cv.Schema(
                {
                    cv.Optional(CONF_MAX_FAILURES, default=5): cv.int_range(
                        min=1, max=255
                    ),
                    cv.Optional(
                        CONF_LOCKOUT, default="5min"
                    ): cv.positive_time_period_milliseconds,
                }
            ),
            **{
                cv.Optional(name): automation.validate_automation(
                    {cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(cls)}
                )
                for name, cls in TRIGGER_CLASSES.items()
            },
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
    if config.get(CONF_REQUIRE_PASSWORD):
        cg.add(var.set_require_password(True))
        cg.add(
            var.set_pbkdf2_iterations(
                config.get(CONF_PBKDF2_ITERATIONS, DEFAULT_PBKDF2_ITERATIONS)
            )
        )
    if CONF_ADMIN_TOKEN in config:
        cg.add(var.set_admin_token(config[CONF_ADMIN_TOKEN]))
    if CONF_MAX_ACTIVE_TIME in config:
        cg.add(var.set_max_active_time(config[CONF_MAX_ACTIVE_TIME]))
    if CONF_IDLE_TIMEOUT in config:
        cg.add(var.set_idle_timeout(config[CONF_IDLE_TIMEOUT]))
    backoff = config[CONF_AUTH_BACKOFF]
    cg.add(var.set_auth_backoff(backoff[CONF_MAX_FAILURES], backoff[CONF_LOCKOUT]))

    for name, (_, args) in TRIGGERS.items():
        for conf in config.get(name, []):
            trigger = cg.new_Pvariable(conf[CONF_TRIGGER_ID], var)
            await automation.build_automation(trigger, args, conf)

    # ES512 signatures for P-521 and the S384/S512 thumbprints. ESPHome turns
    # SHA-384/512 off on ESP-IDF 6 unless a component asks for them.
    esp32.require_mbedtls_sha512()


TANG_SERVER_ID_SCHEMA = automation.maybe_simple_id(
    {cv.GenerateID(): cv.use_id(TangServer)}
)


def check_activate_password(has_password, what="tang_server.activate", option="a password"):
    """Activation takes a password exactly when the component requires one,
    like /activate. An action's or entity's schema cannot see the component's
    configuration, so this runs in their code generation. One tang_server per
    device, so its configuration is CORE.config["tang_server"]."""
    server = CORE.config["tang_server"]
    if server[CONF_KEY_STORAGE] != "nvs":
        raise EsphomeError(f"{what} needs key_storage: nvs")
    required = server.get(CONF_REQUIRE_PASSWORD, False)
    if required and not has_password:
        raise EsphomeError(f"{what} needs {option}: tang_server has require_password")
    if has_password and not required:
        raise EsphomeError(f"{what} takes no {option.removeprefix('a ')}: tang_server has no require_password")


@automation.register_action(
    "tang_server.activate",
    ActivateAction,
    cv.Schema(
        {
            cv.GenerateID(): cv.use_id(TangServer),
            cv.Optional(CONF_PASSWORD): cv.templatable(cv.sensitive(cv.string)),
        }
    ),
    # Returns at once; the activation continues in its own task.
    synchronous=True,
)
async def activate_action_to_code(config, action_id, template_arg, args):
    check_activate_password(CONF_PASSWORD in config)
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    if CONF_PASSWORD in config:
        password = await cg.templatable(config[CONF_PASSWORD], args, cg.std_string)
        cg.add(var.set_password(password))
    return var


@automation.register_action(
    "tang_server.deactivate",
    DeactivateAction,
    TANG_SERVER_ID_SCHEMA,
    synchronous=True,
)
@automation.register_action(
    "tang_server.wipe", WipeAction, TANG_SERVER_ID_SCHEMA, synchronous=True
)
async def server_action_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    return cg.new_Pvariable(action_id, template_arg, parent)


@automation.register_condition(
    "tang_server.is_active", IsActiveCondition, TANG_SERVER_ID_SCHEMA
)
@automation.register_condition(
    "tang_server.is_locked", IsLockedCondition, TANG_SERVER_ID_SCHEMA
)
@automation.register_condition(
    "tang_server.is_provisioned", IsProvisionedCondition, TANG_SERVER_ID_SCHEMA
)
async def server_condition_to_code(config, condition_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    return cg.new_Pvariable(condition_id, template_arg, parent)
