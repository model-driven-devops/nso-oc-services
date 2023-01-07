#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_vlans.json, save the
NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_ned_configuration_remaining_vlans.json, and save the MDD OpenConfig configuration to a file named
{nso_device}_openconfig_vlans.json.

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

vlans_notes = []

openconfig_vlans = {
    "openconfig-network-instance:network-instances": {
        "openconfig-network-instance:network-instance": [
            {"openconfig-network-instance:name": "default",
             "openconfig-network-instance:config": {
                 "openconfig-network-instance:name": "default",
                 "openconfig-network-instance:type": "DEFAULT_INSTANCE",
                 "openconfig-network-instance:enabled": "true"
             },
             "openconfig-network-instance:vlans": {
                 "openconfig-network-instance:vlan": [
                 ]
             }
             }
        ]
    }
}


def xe_create_vlans(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig Network Instances VLANs
    """
    openconfig_network_instance_vlans = \
        openconfig_vlans["openconfig-network-instance:network-instances"][
            "openconfig-network-instance:network-instance"][
            0]["openconfig-network-instance:vlans"]["openconfig-network-instance:vlan"]

    if config_before.get("tailf-ned-cisco-ios:vlan", {}).get("vlan-list"):
        for vlan in config_before["tailf-ned-cisco-ios:vlan"]["vlan-list"]:
            status = "ACTIVE"
            if vlan.get("shutdown"):
                status = "SUSPENDED"
            temp = {"openconfig-network-instance:vlan-id": vlan.get("id"),
                    "openconfig-network-instance:config": {
                        "openconfig-network-instance:vlan-id": vlan.get("id"),
                        "openconfig-network-instance:name": vlan.get("name", ""),
                        "openconfig-network-instance:status": status
                    }
                    }
            openconfig_network_instance_vlans.append(temp)
        del config_leftover["tailf-ned-cisco-ios:vlan"]


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
    :return: MDD Openconfig Network instances with VLANS configuration: dict
    """

    xe_create_vlans(before, leftover)
    translation_notes += vlans_notes

    return openconfig_vlans

if __name__ == "__main__":
    sys.path.append("../../")
    sys.path.append("../../../")

    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc import common
    else:
        import common_xe
        import common

    (config_before_dict, config_leftover_dict, interface_ip_dict) = common_xe.init_xe_configs()
    main(config_before_dict, config_leftover_dict)
    config_name = "_vlans"
    config_remaining_name = "_remaining_vlans"
    oc_name = "_openconfig_vlans"
    common.print_and_test_configs("xe1", config_before_dict, config_leftover_dict, openconfig_vlans, 
        config_name, config_remaining_name, oc_name, vlans_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc import common
    else:
        from xe import common_xe
        import common
