#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_spanning_tree.json,
save the NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_ned_configuration_remaining_spanning_tree.json, and save the MDD OpenConfig configuration to a file
named {nso_device}_openconfig_spanning_tree.json.

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

openconfig_spanning_tree = {
    "openconfig-spanning-tree:stp": {
        "openconfig-spanning-tree:global": {
            "openconfig-spanning-tree:config": {}
        },
        "openconfig-spanning-tree:interfaces": {
            "openconfig-spanning-tree:interface": []
        },
        "openconfig-spanning-tree:rapid-pvst": {
            "openconfig-spanning-tree:vlan": []
        },
        "openconfig-spanning-tree-ext:pvst": {
            "openconfig-spanning-tree-ext:vlan": []
        },
        "openconfig-spanning-tree:mstp": {
            "openconfig-spanning-tree:vlan": []
        }
    }
}

stp_modes = {
    "mst": "MSTP",
    "rapid-pvst": "RAPID_PVST",
    "pvst": "PVST"
}

stp_interface_types = [
    "Ethernet",
    "FastEthernet",
    "FortyGigabitEthernet",
    "GigabitEthernet",
    "HundredGigE",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "TwoGigabitEthernet",
    "Port-channel"
]

stp_guard_types = {
    "none": "NONE",
    "root": "ROOT",
    "loop": "LOOP"
}

stp_link_types = {
    "shared": "SHARED",
    "point-to-point": "P2P"
}


def xe_spanning_tree_global(config_before: dict, config_leftover: dict) -> None:
    if type(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("loopguard", {}).get("default", "")) is list:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:loop-guard"] = True
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["loopguard"]
    else:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:loop-guard"] = False

    if type(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("etherchannel", {}).get("guard", {}).get(
            "misconfig", "")) is list:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:etherchannel-misconfig-guard"] = True
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["etherchannel"]["guard"]
    else:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:etherchannel-misconfig-guard"] = False

    if type(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("portfast", {}).get("edge", {}).get(
            "bpduguard", {}).get("default", "")) is list:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:bpdu-guard"] = True
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["portfast"]["edge"]["bpduguard"]
    else:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:bpdu-guard"] = False

    if type(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("portfast", {}).get("edge", {}).get(
            "bpdufilter", {}).get("default", "")) is list:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:bpdu-filter"] = True
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["portfast"]["edge"]["bpdufilter"]
    else:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:bpdu-filter"] = False


def xe_configure_rpvst_vlans(config_before: dict, config_leftover: dict, stp_interfaces: list) -> None:
    if len(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("vlan", {}).get("vlan-list", [])) > 0:
        for cdb_vlan in config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("vlan", {}).get("vlan-list", []):
            temp_service_vlan_dict = {"openconfig-spanning-tree:vlan-id": cdb_vlan.get("id"),
                                      "openconfig-spanning-tree:config": {
                                          "openconfig-spanning-tree:vlan-id": cdb_vlan.get("id")
                                      }}
            if cdb_vlan.get("hello-time"):
                temp_service_vlan_dict["openconfig-spanning-tree:config"][
                    "openconfig-spanning-tree:hello-time"] = cdb_vlan.get("hello-time")
            else:
                temp_service_vlan_dict["openconfig-spanning-tree:config"][
                    "openconfig-spanning-tree:hello-time"] = 2
            if cdb_vlan.get("forward-time"):
                temp_service_vlan_dict["openconfig-spanning-tree:config"][
                    "openconfig-spanning-tree:forwarding-delay"] = cdb_vlan.get("forward-time")
            else:
                temp_service_vlan_dict["openconfig-spanning-tree:config"][
                    "openconfig-spanning-tree:forwarding-delay"] = 15
            if cdb_vlan.get("max-age"):
                temp_service_vlan_dict["openconfig-spanning-tree:config"][
                    "openconfig-spanning-tree:max-age"] = cdb_vlan.get("max-age")
            else:
                temp_service_vlan_dict["openconfig-spanning-tree:config"][
                    "openconfig-spanning-tree:max-age"] = 20
            if cdb_vlan.get("priority"):
                temp_service_vlan_dict["openconfig-spanning-tree:config"][
                    "openconfig-spanning-tree:bridge-priority"] = cdb_vlan.get("priority")
            else:
                temp_service_vlan_dict["openconfig-spanning-tree:config"][
                    "openconfig-spanning-tree:bridge-priority"] = 32868
            if stp_interfaces:
                temp_service_vlan_dict.update({"openconfig-spanning-tree:interfaces": {
                    "openconfig-spanning-tree:interface": stp_interfaces
                }})
            openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:rapid-pvst"][
                "openconfig-spanning-tree:vlan"].append(temp_service_vlan_dict)

        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["vlan"]["vlan-list"]


def xe_configure_pvst_vlans(config_before: dict, config_leftover: dict, stp_interfaces: list) -> None:
    if len(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("vlan", {}).get("vlan-list", [])) > 0:
        for cdb_vlan in config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("vlan", {}).get("vlan-list", []):
            temp_service_vlan_dict = {"openconfig-spanning-tree-ext:vlan-id": cdb_vlan.get("id"),
                                      "openconfig-spanning-tree-ext:config": {
                                          "openconfig-spanning-tree-ext:vlan-id": cdb_vlan.get("id")
                                      }}
            if cdb_vlan.get("hello-time"):
                temp_service_vlan_dict["openconfig-spanning-tree-ext:config"][
                    "openconfig-spanning-tree-ext:hello-time"] = cdb_vlan.get("hello-time")
            else:
                temp_service_vlan_dict["openconfig-spanning-tree-ext:config"][
                    "openconfig-spanning-tree-ext:hello-time"] = 2
            if cdb_vlan.get("forward-time"):
                temp_service_vlan_dict["openconfig-spanning-tree-ext:config"][
                    "openconfig-spanning-tree-ext:forwarding-delay"] = cdb_vlan.get("forward-time")
            else:
                temp_service_vlan_dict["openconfig-spanning-tree-ext:config"][
                    "openconfig-spanning-tree-ext:forwarding-delay"] = 15
            if cdb_vlan.get("max-age"):
                temp_service_vlan_dict["openconfig-spanning-tree-ext:config"][
                    "openconfig-spanning-tree-ext:max-age"] = 20
            else:
                temp_service_vlan_dict["openconfig-spanning-tree-ext:config"][
                    "openconfig-spanning-tree-ext:max-age"] = cdb_vlan.get("max-age")
            if cdb_vlan.get("priority"):
                temp_service_vlan_dict["openconfig-spanning-tree-ext:config"][
                    "openconfig-spanning-tree-ext:bridge-priority"] = cdb_vlan.get("priority")
            else:
                temp_service_vlan_dict["openconfig-spanning-tree-ext:config"][
                    "openconfig-spanning-tree-ext:bridge-priority"] = 32868
            if stp_interfaces:
                temp_service_vlan_dict.update({"openconfig-spanning-tree-ext:interfaces": {
                    "openconfig-spanning-tree-ext:interface": stp_interfaces
                }})
            openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree-ext:pvst"][
                "openconfig-spanning-tree-ext:vlan"].append(temp_service_vlan_dict)
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["vlan"]["vlan-list"]


def xe_spanning_tree_interfaces(config_before: dict, config_leftover: dict) -> None:
    for interface_type in config_before.get("tailf-ned-cisco-ios:interface", {}):
        if interface_type in stp_interface_types:
            for nso_index, interface in enumerate(
                    config_before.get("tailf-ned-cisco-ios:interface", {}).get(interface_type)):
                if type(interface.get("switchport", "")) is dict:
                    service_interface_dict = {"openconfig-spanning-tree:name": f"{interface_type}{interface['name']}",
                                              "openconfig-spanning-tree:config": {
                                                  "openconfig-spanning-tree:name": f"{interface_type}{interface['name']}"}
                                              }
                    if interface.get("spanning-tree", {}).get("guard"):
                        service_interface_dict["openconfig-spanning-tree:config"][
                            "openconfig-spanning-tree:guard"] = stp_guard_types.get(
                            interface.get("spanning-tree", {}).get("guard"))
                        del \
                            config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                "spanning-tree"][
                                "guard"]
                    if type(interface.get("spanning-tree", {}).get("bpduguard", {}).get("enable", "")) is list:
                        service_interface_dict["openconfig-spanning-tree:config"][
                            "openconfig-spanning-tree:bpdu-guard"] = True
                        del \
                            config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                "spanning-tree"][
                                "bpduguard"]
                    else:
                        service_interface_dict["openconfig-spanning-tree:config"][
                            "openconfig-spanning-tree:bpdu-guard"] = False
                    if interface.get("spanning-tree", {}).get("link-type") == "shared" or interface.get("spanning-tree",
                                                                                                        {}).get(
                            "link-type") == "point-to-point":
                        service_interface_dict["openconfig-spanning-tree:config"][
                            "openconfig-spanning-tree:link-type"] = stp_link_types.get(
                            interface.get("spanning-tree", {}).get("link-type"))
                        del \
                            config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                "spanning-tree"][
                                "link-type"]
                    if not interface.get("spanning-tree", {}).get("bpdufilter"):
                        service_interface_dict["openconfig-spanning-tree:config"][
                            "openconfig-spanning-tree:bpdu-filter"] = False
                    elif interface.get("spanning-tree", {}).get("bpdufilter") == "disable":
                        service_interface_dict["openconfig-spanning-tree:config"][
                            "openconfig-spanning-tree:bpdu-filter"] = False
                        del \
                            config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                "spanning-tree"][
                                "bpdufilter"]
                    elif interface.get("spanning-tree", {}).get("bpdufilter") == "enable":
                        service_interface_dict["openconfig-spanning-tree:config"][
                            "openconfig-spanning-tree:bpdu-filter"] = True
                        del \
                            config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                "spanning-tree"][
                                "bpdufilter"]
                    if type(interface.get("spanning-tree", {}).get("portfast", {}).get("disable", "")) is list:
                        service_interface_dict["openconfig-spanning-tree:config"][
                            "openconfig-spanning-tree:edge-port"] = "EDGE_DISABLE"
                        del \
                            config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                "spanning-tree"][
                                "portfast"]
                    elif type(interface.get("spanning-tree", {}).get("portfast", "")) is dict:
                        service_interface_dict["openconfig-spanning-tree:config"][
                            "openconfig-spanning-tree:edge-port"] = "EDGE_ENABLE"
                        del \
                            config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                "spanning-tree"][
                                "portfast"]
                    elif type(interface.get("switchport", {}).get("mode", {}).get("access", "")) is dict and type(
                            config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("portfast", {}).get(
                                    "default", "")) is list:
                        service_interface_dict["openconfig-spanning-tree:config"][
                            "openconfig-spanning-tree:edge-port"] = "EDGE_AUTO"
                    openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:interfaces"][
                        "openconfig-spanning-tree:interface"].append(service_interface_dict)


def get_stp_interfaces_rpvst(config_before: dict, config_leftover: dict) -> list:
    stp_interfaces = []
    for interface_type in config_before.get("tailf-ned-cisco-ios:interface", {}):
        if interface_type in stp_interface_types:
            for nso_index, interface in enumerate(
                    config_before.get("tailf-ned-cisco-ios:interface", {}).get(interface_type)):
                if type(interface.get("switchport", "")) is dict:
                    if interface.get("spanning-tree", {}).get("cost") or interface.get("spanning-tree", {}).get(
                            "port-priority"):
                        temp_dict = {"openconfig-spanning-tree:name": f"{interface_type}{interface['name']}",
                                     "openconfig-spanning-tree:config": {
                                         "openconfig-spanning-tree:name": f"{interface_type}{interface['name']}"
                                     }}
                        if interface.get("spanning-tree", {}).get("cost"):
                            temp_dict["openconfig-spanning-tree:config"][
                                "openconfig-spanning-tree:cost"] = interface.get(
                                "spanning-tree", {}).get("cost")
                            del \
                                config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                    "spanning-tree"][
                                    "cost"]
                        if interface.get("spanning-tree", {}).get("port-priority"):
                            temp_dict["openconfig-spanning-tree:config"][
                                "openconfig-spanning-tree:port-priority"] = interface.get("spanning-tree", {}).get(
                                "port-priority")
                            del \
                                config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                    "spanning-tree"][
                                    "port-priority"]
                        stp_interfaces.append(temp_dict)
    return stp_interfaces


def get_stp_interfaces_pvst(config_before: dict, config_leftover: dict) -> list:
    stp_interfaces = []
    for interface_type in config_before.get("tailf-ned-cisco-ios:interface", {}):
        if interface_type in stp_interface_types:
            for nso_index, interface in enumerate(
                    config_before.get("tailf-ned-cisco-ios:interface", {}).get(interface_type)):
                if type(interface.get("switchport", "")) is dict:
                    if interface.get("spanning-tree", {}).get("cost") or interface.get("spanning-tree", {}).get(
                            "port-priority"):
                        temp_dict = {"openconfig-spanning-tree-ext:name": f"{interface_type}{interface['name']}",
                                     "openconfig-spanning-tree-ext:config": {
                                         "openconfig-spanning-tree-ext:name": f"{interface_type}{interface['name']}"
                                     }}
                        if interface.get("spanning-tree", {}).get("cost"):
                            temp_dict["openconfig-spanning-tree-ext:config"][
                                "openconfig-spanning-tree-ext:cost"] = interface.get(
                                "spanning-tree", {}).get("cost")
                            del \
                                config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                    "spanning-tree"][
                                    "cost"]
                        if interface.get("spanning-tree", {}).get("port-priority"):
                            temp_dict["openconfig-spanning-tree-ext:config"][
                                "openconfig-spanning-tree-ext:port-priority"] = interface.get("spanning-tree", {}).get(
                                "port-priority")
                            del \
                                config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                    "spanning-tree"][
                                    "port-priority"]
                        stp_interfaces.append(temp_dict)
    return stp_interfaces


def xe_spanning_tree(config_before: dict, config_leftover: dict) -> dict:
    """
    Translates NSO XE NED to MDD OpenConfig Spanning-tree
    """
    if config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("mode") == "pvst" or config_before.get(
            "tailf-ned-cisco-ios:spanning-tree", {}).get("mode") == "rapid-pvst" or config_before.get(
        "tailf-ned-cisco-ios:spanning-tree", {}).get("mode") == "mst":
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:enabled-protocol"] = [stp_modes.get(
            config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("mode"))]
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["mode"]
    else:
        return openconfig_spanning_tree
    xe_spanning_tree_global(config_before, config_leftover)

    # PVST
    if config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("mode") == "pvst":
        stp_interfaces = get_stp_interfaces_pvst(config_before, config_leftover)
        xe_configure_pvst_vlans(config_before, config_leftover, stp_interfaces)
        # Uplinkfast
        if type(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("uplinkfast", "")) is list:
            openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
                "openconfig-spanning-tree:config"]["openconfig-spanning-tree-ext:uplinkfast"] = True
            del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["uplinkfast"]
        else:
            openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
                "openconfig-spanning-tree:config"]["openconfig-spanning-tree-ext:uplinkfast"] = False
        # Backbonefast
        if type(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("backbonefast", "")) is list:
            openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
                "openconfig-spanning-tree:config"]["openconfig-spanning-tree-ext:backbonefast"] = True
            del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["backbonefast"]
        else:
            openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
                "openconfig-spanning-tree:config"]["openconfig-spanning-tree-ext:backbonefast"] = False

    # RPVST
    if config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("mode") == "rapid-pvst":
        stp_interfaces = get_stp_interfaces_rpvst(config_before, config_leftover)
        xe_configure_rpvst_vlans(config_before, config_leftover, stp_interfaces)

    # MSTP
    if config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("mode") == "rapid-pvst":
        pass

    # Interfaces
    xe_spanning_tree_interfaces(config_before, config_leftover)


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

    xe_spanning_tree(before, leftover)

    return openconfig_spanning_tree


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
    config_name = "ned_configuration_spanning_tree"
    config_remaining_name = "ned_configuration_remaining_spanning_tree"
    oc_name = "openconfig_spanning_tree"
    common.print_and_test_configs(
        "xeswitch1", config_before_dict, config_leftover_dict, openconfig_spanning_tree,
        config_name, config_remaining_name, oc_name)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
    else:
        from xe import common_xe
