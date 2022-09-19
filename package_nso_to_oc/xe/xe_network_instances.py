#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_network_instances.json,
save the NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_ned_configuration_remaining_network_instances.json, and save the MDD OpenConfig configuration to a file
named {nso_device}_openconfig_network_instances.json.

The script requires the following environment variables:
NSO_HOST - IP address or hostname for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation
TEST - True or False. True enables sending the OpenConfig to the NSO server after generation
"""

import sys
from pathlib import Path
from importlib.util import find_spec

openconfig_network_instances = {
    "openconfig-network-instance:network-instances": {
        "openconfig-network-instance:network-instance": [
            {"openconfig-network-instance:name": "default",
             "openconfig-network-instance:config": {
                 "openconfig-network-instance:name": "default",
                 "openconfig-network-instance:type": "DEFAULT_INSTANCE",
                 "openconfig-network-instance:enabled": "true"
                 }
             }
        ]
    }
}


def xe_network_instances(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig Network Instances
    """
    if config_before.get("tailf-ned-cisco-ios:vrf", {}).get("definition"):
        for vrf_index, vrf in enumerate(config_before.get("tailf-ned-cisco-ios:vrf", {}).get("definition")):
            if vrf.get("address-family"):
                address_families = []
                for key in vrf.get("address-family").keys():
                    if key == "ipv4":
                        address_families.append("openconfig-types:IPV4")
                    if key == "ipv6":
                        address_families.append("openconfig-types:IPV6")
                temp_vrf = {"openconfig-network-instance:name": vrf["name"],
                            "openconfig-network-instance:config": {
                                "openconfig-network-instance:name": vrf["name"],
                                "openconfig-network-instance:type": "L3VRF",
                                "openconfig-network-instance:enabled": "true",
                                "openconfig-network-instance:enabled-address-families": address_families
                            }}
                del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["address-family"]
            openconfig_network_instances["openconfig-network-instance:network-instances"][
                "openconfig-network-instance:network-instance"].append(temp_vrf)


def main(before: dict, leftover: dict) -> dict:
    """
    Translates NSO Device configurations to MDD OpenConfig configurations.

    Requires environment variables:
    NSO_HOST: str
    NSO_USERNAME: str
    NSO_PASSWORD: str
    NSO_DEVICE: str
    TEST - If True, sends generated OC configuration to NSO Server: str

    :param before: Original NSO Device configuration: dict
    :param leftover: NSO Device configuration minus configs replaced with MDD OC: dict
    :return: MDD Openconfig Network Instances configuration: dict
    """

    xe_network_instances(before, leftover)

    return openconfig_network_instances

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
    config_name = "ned_configuration_network_instances"
    config_remaining_name = "ned_configuration_remaining_network_instances"
    oc_name = "openconfig_network_instances"
    common.print_and_test_configs(
        "xe1", config_before_dict, config_leftover_dict, openconfig_network_instances, 
        config_name, config_remaining_name, oc_name)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
    else:
        from xe import common_xe
