#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_spanning_tree.json,
save the NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_ned_configuration_remaining_spanning_tree.json, and save the MDD OpenConfig configuration to a file
named {nso_device}_openconfig_spanning_tree.json.

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

stp_notes = []

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
            "openconfig-spanning-tree:config": {},
            "openconfig-spanning-tree:mst-instances": {
                "openconfig-spanning-tree:mst-instance": []
            }
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

    # Unreliable - Enabled by default on device. NSO NED doesn't show enabled when device added to NSO.
    # Hence we can't configure etherchannel-misconfig-guard = False if the configu is missing from NSO.
    # if type(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("etherchannel", {}).get("guard", {}).get(
    #         "misconfig", "")) is list:
    #     openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
    #         "openconfig-spanning-tree:config"]["openconfig-spanning-tree:etherchannel-misconfig-guard"] = True
    #     del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["etherchannel"]["guard"]
    # else:
    #     openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
    #         "openconfig-spanning-tree:config"]["openconfig-spanning-tree:etherchannel-misconfig-guard"] = False

    if type(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("portfast", {}).get("edge", {}).get(
            "bpduguard", {}).get("default", "")) is list:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:bpdu-guard"] = True
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["portfast"]["edge"]["bpduguard"]
    elif type(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("portfast", {}).get(
            "bpduguard", {}).get("default", "")) is list:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:bpdu-guard"] = True
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["portfast"]["bpduguard"]
    else:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:bpdu-guard"] = False

    if type(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("portfast", {}).get("edge", {}).get(
            "bpdufilter", {}).get("default", "")) is list:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:bpdu-filter"] = True
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["portfast"]["edge"]["bpdufilter"]
    elif type(config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("portfast", {}).get(
            "bpdufilter", {}).get("default", "")) is list:
        openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:global"][
            "openconfig-spanning-tree:config"]["openconfig-spanning-tree:bpdu-filter"] = True
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["portfast"]["bpdufilter"]
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
                    "openconfig-spanning-tree-ext:max-age"] = cdb_vlan.get("max-age")
            else:
                temp_service_vlan_dict["openconfig-spanning-tree-ext:config"][
                    "openconfig-spanning-tree-ext:max-age"] = 20
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


def get_stp_interfaces_mstp(config_before: dict, config_leftover: dict) -> dict:
    """
    Return dict with instances as keys and list of interfaces as value
    """
    mstp_instances_interfaces_dict = {}
    for interface_type in config_before.get("tailf-ned-cisco-ios:interface", {}):
        if interface_type in stp_interface_types:
            for nso_index, interface in enumerate(
                    config_before.get("tailf-ned-cisco-ios:interface", {}).get(interface_type)):
                if type(interface.get("switchport", "")) is dict:
                    if len(interface.get("spanning-tree", {}).get("mst", {}).get("instance-range")) > 0:
                        for instance_index, cdb_interface_instance in enumerate(
                                interface.get("spanning-tree", {}).get("mst", {}).get("instance-range")):
                            if cdb_interface_instance.get("id") not in mstp_instances_interfaces_dict.keys():
                                mstp_instances_interfaces_dict[cdb_interface_instance.get("id")] = []

                            temp_dict = {"openconfig-spanning-tree:name": f"{interface_type}{interface['name']}",
                                         "openconfig-spanning-tree:config": {
                                             "openconfig-spanning-tree:name": f"{interface_type}{interface['name']}"
                                         }}
                            if cdb_interface_instance.get("cost"):
                                temp_dict["openconfig-spanning-tree:config"][
                                    "openconfig-spanning-tree:cost"] = cdb_interface_instance.get("cost")
                                del \
                                    config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                        "spanning-tree"]["mst"]["instance-range"][instance_index]["cost"]
                            if cdb_interface_instance.get("port-priority"):
                                temp_dict["openconfig-spanning-tree:config"][
                                    "openconfig-spanning-tree:port-priority"] = cdb_interface_instance.get(
                                    "port-priority")
                                del \
                                    config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index][
                                        "spanning-tree"]["mst"]["instance-range"][instance_index]["port-priority"]
                            mstp_instances_interfaces_dict[cdb_interface_instance.get("id")].append(temp_dict)
    return mstp_instances_interfaces_dict


def get_cdb_mst_instance_info(config_before: dict, config_leftover: dict) -> dict:
    """
    Parses tailf-ned-cisco-ios:spanning-tree for instance priorities and vlan ranges
    returns dict, e.g. {$mst-id: {'priority': "16384", 'vlans': [10,11,12]}}
    """
    mst_instances = {}
    for instance_index, instance in enumerate(
            config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("mst", {}).get("instance-range")):
        if instance.get("id") not in mst_instances.keys():
            mst_instances[instance.get("id")] = {}
        if instance.get("priority"):
            mst_instances[instance.get("id")]["priority"] = instance.get("priority")
            del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["mst"]["instance-range"][instance_index][
                "priority"]
    for instance_index, instance in enumerate(
            config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("mst", {}).get("configuration", {}).get(
                    "instance")):
        if instance.get("id") not in mst_instances.keys():
            mst_instances[instance.get("id")] = {}
        if len(instance.get("vlan", [])) > 0:
            mst_instances[instance.get("id")]["vlans"] = instance.get("vlan", [])
            del \
            config_leftover["tailf-ned-cisco-ios:spanning-tree"]["mst"]["configuration"]["instance"][instance_index][
                "vlan"]
    return mst_instances


def xe_configure_mstp(config_before: dict, config_leftover: dict, stp_interfaces: dict) -> None:
    oc_mstp = openconfig_spanning_tree["openconfig-spanning-tree:stp"]["openconfig-spanning-tree:mstp"]
    if config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("mst", {}).get("configuration", {}).get("name"):
        oc_mstp["openconfig-spanning-tree:config"]["openconfig-spanning-tree:name"] = config_before.get(
            "tailf-ned-cisco-ios:spanning-tree", {}).get("mst", {}).get("configuration", {}).get("name")
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["mst"]["configuration"]["name"]
    if config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("mst", {}).get("configuration", {}).get(
            "revision"):
        oc_mstp["openconfig-spanning-tree:config"]["openconfig-spanning-tree:revision"] = config_before.get(
            "tailf-ned-cisco-ios:spanning-tree", {}).get("mst", {}).get("configuration", {}).get("revision")
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["mst"]["configuration"]["revision"]
    if config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("mst", {}).get("forward-time"):
        oc_mstp["openconfig-spanning-tree:config"]["openconfig-spanning-tree:forwarding-delay"] = config_before.get(
            "tailf-ned-cisco-ios:spanning-tree", {}).get("mst", {}).get("forward-time")
        del config_leftover["tailf-ned-cisco-ios:spanning-tree"]["mst"]["forward-time"]

    mst_instances = get_cdb_mst_instance_info(config_before, config_leftover)

    for mst_instance_id, mst_values in mst_instances.items():
        temp_instance_dict = {"openconfig-spanning-tree:mst-id": mst_instance_id,
                              "openconfig-spanning-tree:config": {
                                  "openconfig-spanning-tree:mst-id": mst_instance_id,
                              },
                              "openconfig-spanning-tree:interfaces": {
                                  "openconfig-spanning-tree:interface": []
                              }}
        if mst_values.get("vlans"):
            temp_instance_dict["openconfig-spanning-tree:config"]["openconfig-spanning-tree:vlan"] = mst_values.get(
                "vlans")
        if mst_values.get("priority"):
            temp_instance_dict["openconfig-spanning-tree:config"][
                "openconfig-spanning-tree:bridge-priority"] = mst_values.get("priority")
        if mst_instance_id in stp_interfaces.keys():
            temp_instance_dict["openconfig-spanning-tree:interfaces"]["openconfig-spanning-tree:interface"].extend(
                stp_interfaces[mst_instance_id])
        oc_mstp["openconfig-spanning-tree:mst-instances"]["openconfig-spanning-tree:mst-instance"].append(
            temp_instance_dict)


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
    if config_before.get("tailf-ned-cisco-ios:spanning-tree", {}).get("mode") == "mst":
        stp_interfaces_mstp = get_stp_interfaces_mstp(config_before, config_leftover)
        xe_configure_mstp(config_before, config_leftover, stp_interfaces_mstp)
    # Interfaces
    xe_spanning_tree_interfaces(config_before, config_leftover)


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

    xe_spanning_tree(before, leftover)
    translation_notes += stp_notes

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
    config_name = "_spanning_tree"
    config_remaining_name = "_remaining_spanning_tree"
    oc_name = "_openconfig_spanning_tree"
    common.print_and_test_configs(
        "xeswitch1", config_before_dict, config_leftover_dict, openconfig_spanning_tree,
        config_name, config_remaining_name, oc_name, stp_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc import common
    else:
        from xe import common_xe
        import common
