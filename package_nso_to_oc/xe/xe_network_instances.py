#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_network_instances.json,
save the NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_ned_configuration_remaining_network_instances.json, and save the MDD OpenConfig configuration to a file
named {nso_device}_openconfig_network_instances.json.

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
import copy

network_instances_notes = []

openconfig_network_instances = {
    "openconfig-network-instance:network-instances": {
        "openconfig-network-instance:network-instance": [
            {
                "openconfig-network-instance:name": "default",
                "openconfig-network-instance:config": {
                    "openconfig-network-instance:name": "default",
                    "openconfig-network-instance:type": "DEFAULT_INSTANCE",
                    "openconfig-network-instance:enabled": "true"
                },
                "openconfig-network-instance:protocols": {"openconfig-network-instance:protocol": []},
                "openconfig-network-instance:interfaces": {"openconfig-network-instance:interface": []}
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
                temp_vrf = {
                    "openconfig-network-instance:name": vrf["name"],
                    "openconfig-network-instance:config": {
                        "openconfig-network-instance:name": vrf["name"],
                        "openconfig-network-instance:type": "L3VRF",
                        "openconfig-network-instance:enabled": "true",
                        "openconfig-network-instance:enabled-address-families": address_families
                    },
                    "openconfig-network-instance:protocols": {"openconfig-network-instance:protocol": []},
                    "openconfig-network-instance:interfaces": {"openconfig-network-instance:interface": []}
                }
                del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["address-family"]
            openconfig_network_instances["openconfig-network-instance:network-instances"][
                "openconfig-network-instance:network-instance"].append(temp_vrf)

    interfaces_by_vrf = get_interfaces_by_vrf(config_before)
    configure_network_instances(config_before, config_leftover, interfaces_by_vrf)

def get_interfaces_by_vrf(config_before):
    interfaces_by_vrf = {}
    interfaces = config_before.get("tailf-ned-cisco-ios:interface", {})
    for interface_type, interface_list in interfaces.items():
        if interface_type == "Port-channel-subinterface":
            interface_type = "Port-channel"
            interface_list = interface_list[interface_type]

        for interface in interface_list:
            if (not "ip" in interface or not "address" in interface["ip"] 
                or not "primary" in interface["ip"]["address"] or not "address" in interface["ip"]["address"]["primary"]):
                continue

            interface_copy = copy.deepcopy(interface)
            interface_copy["type"] = interface_type
            # Ensure we get a string type
            interface_copy["name"] = str(interface_copy["name"])

            if "vrf" in interface_copy and "forwarding" in interface_copy["vrf"]:
                vrf_name = interface_copy["vrf"]["forwarding"]
            else:
                vrf_name = "default"

            if not vrf_name in interfaces_by_vrf:
                interfaces_by_vrf[vrf_name] = []

            interfaces_by_vrf[vrf_name].append(interface_copy)

    return interfaces_by_vrf

def configure_network_instances(config_before, config_leftover, interfaces_by_vrf):
    for net_inst in openconfig_network_instances["openconfig-network-instance:network-instances"][
        "openconfig-network-instance:network-instance"]:
        configure_network_interfaces(net_inst, interfaces_by_vrf)

        if len(interfaces_by_vrf.get(net_inst["openconfig-network-instance:name"], [])) > 0:
            vrf_interfaces = interfaces_by_vrf.get(net_inst["openconfig-network-instance:name"])
            xe_ospfv2.configure_xe_ospf(net_inst, vrf_interfaces, config_before, config_leftover)

def configure_network_interfaces(net_inst, interfaces_by_vrf):
    for interface in interfaces_by_vrf.get(net_inst["openconfig-network-instance:name"], []):
        name_split = interface["name"].split(".")
        primary_interface = name_split[0]
        new_interface = {
            "openconfig-network-instance:id": interface["type"] + interface["name"],
            "openconfig-network-instance:config": {
                "openconfig-network-instance:id": interface["type"] + interface["name"],
                "openconfig-network-instance:interface": interface["type"] + primary_interface
            }
        }

        if (interface["type"] != "Tunnel"):
            subinterface = '0' if len(name_split) == 1 else name_split[1]
            new_interface["openconfig-network-instance:config"]["openconfig-network-instance:subinterface"] = subinterface

        net_inst["openconfig-network-instance:interfaces"]["openconfig-network-instance:interface"].append(new_interface)


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
    :return: MDD Openconfig Network Instances configuration: dict
    """

    xe_network_instances(before, leftover)
    translation_notes += network_instances_notes

    return openconfig_network_instances

if __name__ == "__main__":
    sys.path.append("../../")
    sys.path.append("../../../")

    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc.xe import xe_ospfv2
        from package_nso_to_oc import common
    else:
        import common_xe
        import xe_ospfv2
        import common

    (config_before_dict, config_leftover_dict, interface_ip_dict) = common_xe.init_xe_configs()
    main(config_before_dict, config_leftover_dict)
    config_name = "_network_instances"
    config_remaining_name = "_remaining_network_instances"
    oc_name = "_openconfig_network_instances"
    common.print_and_test_configs(
        "xe1", config_before_dict, config_leftover_dict, openconfig_network_instances, 
        config_name, config_remaining_name, oc_name, network_instances_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc.xe import xe_ospfv2
        from package_nso_to_oc import common
    else:
        from xe import common_xe
        from xe import xe_ospfv2
        import common
