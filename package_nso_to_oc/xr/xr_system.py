#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_configuration.json, save the NSO device
configuration minus parts replaced by OpenConfig to a file named {device_name}_configuration_remaining.json,
and save the MDD OpenConfig configuration to a file named {nso_device}_openconfig.json.

The script requires the following environment variables:
NSO_URL - URL for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation
TEST - True or False. True enables sending the OpenConfig to the NSO server after generation
"""

import sys
from pathlib import Path
from importlib.util import find_spec

system_notes = []

openconfig_system = {
    "openconfig-system:system": {
        "openconfig-system:aaa": {},
        "openconfig-system:clock": {},
        "openconfig-system:config": {},
        "openconfig-system:dns": {},
        "openconfig-system:logging": {},
        "openconfig-system:ntp": {
            "openconfig-system:config": {},
            "openconfig-system:ntp-keys": {
                "openconfig-system:ntp-key": []},
            "openconfig-system:servers": {
                "openconfig-system:server": []}
        },
        "openconfig-system:ssh-server": {
            "openconfig-system:config": {},
            "openconfig-system-ext:algorithm": {
                "openconfig-system-ext:config": {}
            }
        },
        "openconfig-system-ext:services": {"openconfig-system-ext:config": {}}
    }
}


def xr_system_services(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XR NED to MDD OpenConfig System Services
    """
    openconfig_system_services = openconfig_system["openconfig-system:system"]["openconfig-system-ext:services"]
    if type(config_before.get("tailf-ned-cisco-ios-xr:domain", {}).get("lookup", {}).get("disable", "")) is list:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-domain-lookup"] = False
        del config_leftover["tailf-ned-cisco-ios-xr:domain"]["lookup"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-domain-lookup"] = True
    # service tcp-small-servers
    if type(config_before.get("tailf-ned-cisco-ios-xr:service", {}).get("ipv4", {}).get("tcp-small-servers", '')) is dict:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-tcp-small-servers"] = True
        del config_leftover["tailf-ned-cisco-ios-xr:service"]["ipv4"]["tcp-small-servers"]["max-servers"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-tcp-small-servers"] = False
    # service udp-small-servers
    if type(config_before.get("tailf-ned-cisco-ios-xr:service", {}).get("ipv4", {}).get("udp-small-servers", '')) is dict:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-udp-small-servers"] = True
        del config_leftover["tailf-ned-cisco-ios-xr:service"]["ipv4"]["udp-small-servers"]["max-servers"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-udp-small-servers"] = False

def xr_system_config(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System Config
    """
    openconfig_system_config = openconfig_system["openconfig-system:system"]["openconfig-system:config"]
    default_secret = config_before.get("tailf-ned-cisco-ios-xr:line", {}).get("default", {}).get("secret", {})
    console_exec_timeout = config_before.get("tailf-ned-cisco-ios-xr:line", {}).get("console", {}).get("exec-timeout", {})

    openconfig_system_config["openconfig-system:hostname"] = config_before["tailf-ned-cisco-ios-xr:hostname"]
    del config_leftover["tailf-ned-cisco-ios-xr:hostname"]

    if config_before.get("tailf-ned-cisco-ios-xr:banner", {}).get("login", {}).get("message"):
        openconfig_system_config["openconfig-system:login-banner"] = (
            config_before.get("tailf-ned-cisco-ios-xr:banner",{})
            .get("login")
            .get("message")
        )
        del config_leftover["tailf-ned-cisco-ios-xr:banner"]["login"]

    if config_before.get("tailf-ned-cisco-ios-xr:banner", {}).get("motd", {}).get("message"):
        openconfig_system_config["openconfig-system:motd-banner"] = (
            config_before.get("tailf-ned-cisco-ios-xr:banner",{})
            .get("motd")
            .get("message")
        )
        del config_leftover["tailf-ned-cisco-ios-xr:banner"]["motd"]

    if config_before.get("tailf-ned-cisco-ios-xr:domain", {}).get("name"):
        openconfig_system_config["openconfig-system:domain-name"] = (
            config_before.get("tailf-ned-cisco-ios-xr:domain", {})
            .get("name")
        )
        del config_leftover["tailf-ned-cisco-ios-xr:domain"]["name"]

    if default_secret.get("secret") and default_secret.get("type") == "0":
        openconfig_system_config["openconfig-system-ext:enable-secret"] = default_secret.get("secret")
        del config_leftover["tailf-ned-cisco-ios-xr:line"]["default"]["secret"]

    if console_exec_timeout.get('minutes') or console_exec_timeout.get('seconds'):
        seconds = console_exec_timeout.get('minutes') * 60
        seconds += console_exec_timeout.get('seconds', 0)
        openconfig_system_config["openconfig-system-ext:console-exec-timeout-seconds"] = seconds
        del config_leftover["tailf-ned-cisco-ios-xr:line"]["console"]["exec-timeout"]

def xr_system_ssh_server(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XR NED to MDD OpenConfig System SSH Server
    """
    openconfig_system_ssh_server_alg_config = openconfig_system["openconfig-system:system"]["openconfig-system:ssh-server"]["openconfig-system-ext:algorithm"]["openconfig-system-ext:config"]

    if type(config_before.get("tailf-ned-cisco-ios-xr:ssh", {}).get("server", {}).get("algorithms", {}).get("cipher", '')) is list:
        openconfig_system_ssh_server_alg_config["openconfig-system-ext:encryption"] = config_before.get("tailf-ned-cisco-ios-xr:ssh", {}).get("server", {}).get("algorithms", {}).get("cipher")
        del config_leftover["tailf-ned-cisco-ios-xr:ssh"]["server"]["algorithms"]["cipher"]

def main(before: dict, leftover: dict, translation_notes: list = []) -> dict:
    """
    Translates NSO Device configurations to MDD OpenConfig configurations.

    Requires environment variables:
    NSO_URL: str
    NSO_USERNAME: str
    NSO_PASSWORD: str
    NSO_DEVICE: str
    TEST - If True, sends generated OC configuration to NSO Server: str

    :param before: Original NSO Device configuration: dict
    :param leftover: NSO Device configuration minus configs replaced with MDD OC: dict
    :return: MDD Openconfig System configuration: dict
    """

    xr_system_config(before, leftover)
    xr_system_services(before, leftover)
    xr_system_ssh_server(before, leftover)
    translation_notes += system_notes

    return openconfig_system


if __name__ == "__main__":
    sys.path.append("../../")
    sys.path.append("../../../")

    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xr import common_xr
        from package_nso_to_oc import common
    else:
        import common_xr
        import common

    (config_before_dict, config_leftover_dict) = common_xr.init_xr_configs()
    main(config_before_dict, config_leftover_dict)
    config_name = "_system"
    config_remaining_name = "_remaining_system"
    oc_name = "_openconfig_system"
    common.print_and_test_configs("xr1", config_before_dict, config_leftover_dict, openconfig_system, 
        config_name, config_remaining_name, oc_name, system_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xr import common_xr
        from package_nso_to_oc import common
    else:
        from xr import common_xr
        import common
