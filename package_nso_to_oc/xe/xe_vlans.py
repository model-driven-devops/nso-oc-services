#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_vlans.json, save the
NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_ned_configuration_remaining_vlans.json, and save the MDD OpenConfig configuration to a file named
{nso_device}_openconfig_vlans.json.

The script requires the following environment variables:
NSO_HOST - IP address or hostname for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation
TEST - True or False. True enables sending the OpenConfig to the NSO server after generation
"""
import copy
import json

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
    :return: MDD Openconfig Network instances with VLANS configuration: dict
    """

    xe_create_vlans(before, leftover)

    return openconfig_vlans


if __name__ == '__main__':
    import os
    import sys

    sys.path.append('../../')
    sys.path.append('../../../')
    from package_nso_to_oc import common

    nso_host = os.environ.get("NSO_HOST")
    nso_username = os.environ.get("NSO_USERNAME", "ubuntu")
    nso_password = os.environ.get("NSO_PASSWORD", "admin")
    nso_device = os.environ.get("NSO_DEVICE", "xeswitch1")
    test = os.environ.get("TEST", "False")

    config_before_dict = common.nso_get_device_config(nso_host, nso_username, nso_password, nso_device)
    config_leftover_dict = copy.deepcopy(config_before_dict)
    interface_ip_dict = common.xe_system_get_interface_ip_address(config_before_dict)
    main(config_before_dict, config_leftover_dict)

    print(json.dumps(openconfig_vlans, indent=4))
    with open(f"../{nso_device}_ned_configuration_vlans.json", "w") as b:
        b.write(json.dumps(config_before_dict, indent=4))
    with open(f"../{nso_device}_ned_configuration_remaining_vlans.json", "w") as a:
        a.write(json.dumps(config_leftover_dict, indent=4))
    with open(f"../{nso_device}_openconfig_vlans.json", "w") as o:
        o.write(json.dumps(openconfig_vlans, indent=4))

    if test == 'True':
        common.test_nso_program_oc(nso_host, nso_username, nso_password, nso_device, openconfig_vlans)
