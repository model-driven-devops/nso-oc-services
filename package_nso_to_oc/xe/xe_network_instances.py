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
import copy
import json
import pprint

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


if __name__ == '__main__':
    import os
    import sys

    sys.path.append('../../')
    sys.path.append('../../../')
    from package_nso_to_oc import common

    nso_host = os.environ.get("NSO_HOST")
    nso_username = os.environ.get("NSO_USERNAME", "ubuntu")
    nso_password = os.environ.get("NSO_PASSWORD", "admin")
    nso_device = os.environ.get("NSO_DEVICE", "xe1")
    test = os.environ.get("TEST", "False")

    config_before_dict = common.nso_get_device_config(nso_host, nso_username, nso_password, nso_device)
    config_leftover_dict = copy.deepcopy(config_before_dict)
    interface_ip_dict = common.xe_system_get_interface_ip_address(config_before_dict)
    main(config_before_dict, config_leftover_dict)

    print(json.dumps(openconfig_network_instances, indent=4))
    with open(f"../{nso_device}_ned_configuration_network_instances.json", "w") as b:
        b.write(json.dumps(config_before_dict, indent=4))
    with open(f"../{nso_device}_ned_configuration_remaining_network_instances.json", "w") as a:
        a.write(json.dumps(config_leftover_dict, indent=4))
    with open(f"../{nso_device}_openconfig_network_instances.json", "w") as o:
        o.write(json.dumps(openconfig_network_instances, indent=4))

    if test == 'True':
        common.test_nso_program_oc(nso_host, nso_username, nso_password, nso_device, openconfig_network_instances)
