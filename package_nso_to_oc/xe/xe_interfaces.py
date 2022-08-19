#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_interfaces.json, save the
NSO device configuration minus parts replaced by MDD OpenConfig to a file named
{device_name}_ned_configuration_remaining_interfaces.json, and save the MDD OpenConfig configuration to a file named
{nso_device}_openconfig_interfaces.json.

The script requires the following environment variables:
NSO_HOST - IP address or hostname for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation
TEST - True or False. True enables sending the OpenConfig to the NSO server after generation
"""
import copy
import ipaddress
import json
import os
import pprint

openconfig_interfaces = {
    "openconfig-interfaces:interfaces": {
        "openconfig-interfaces:interface": [
        ]
    }
}

nso_to_oc_interface_types = {
    "Ethernet": "ethernetCsmacd",
    "FastEthernet": "ethernetCsmacd",
    "FortyGigabitEthernet": "ethernetCsmacd",
    "GigabitEthernet": "ethernetCsmacd",
    "HundredGigE": "ethernetCsmacd",
    "TenGigabitEthernet": "ethernetCsmacd",
    "TwentyFiveGigE": "ethernetCsmacd",
    "TwoGigabitEthernet": "ethernetCsmacd",
    "Loopback": "softwareLoopback",
    "Tunnel": "tunnel",
    "vasileft": "vasi",
    "vasiright": "vasi",
    "Vlan": "l3ipvlan",
    "Port-channel": "ieee8023adLag",
    "Port-channel-subinterface": "ieee8023adLag"
}


def return_nested_dict(root_dict: dict, keys_list: list) -> dict:
    """
    Return object of nested dictionary
    :param root_dict: full dict
    :param keys_list: list of keys; path to nested dict
    :return: dictionary object referencing nested dictionary
    """
    return_dict = root_dict
    for key in keys_list:
        return_dict = return_dict[key]
    return return_dict


def create_interface_dict(config_before: dict) -> dict:
    """
    Receive NSO configuration, create interface and index dict, and update global openconfig_interfaces
    Note - Interface type can be changed during processing
    :param config_before: dict
    :return: dictionaries of interface types, names, and indexes for nso and OC interface lists

    Example: {'Loopback': {'10': {'oc_interface_index': 0, 'nso_interface_index': 0, 'physical_interface_number': '10',
    'oc_sub_interface_number': 0, 'nso_interface_type': 'Loopback', 'oc_sub_interface_place_counter': 0},
    '100': {'oc_interface_index': 1, 'nso_interface_index': 1, 'physical_interface_number': '100',
    'oc_sub_interface_number': 0, 'nso_interface_type': 'Loopback', 'oc_sub_interface_place_counter': 0}},
    'GigabitEthernet': {'0/0': {'oc_interface_index': 2, 'nso_interface_index': 0, 'physical_interface_number': '0/0',
    'oc_sub_interface_number': 0, 'nso_interface_type': 'GigabitEthernet', 'oc_sub_interface_place_counter': 0},
    '0/1': {'oc_interface_index': 3, 'nso_interface_index': 1, 'physical_interface_number': '0/1',
    'oc_sub_interface_number': 0, 'nso_interface_type': 'GigabitEthernet', 'oc_sub_interface_place_counter': 0},
    '0/2': {'oc_interface_index': 4, 'nso_interface_index': 2, 'physical_interface_number': '0/2',
    'oc_sub_interface_number': 0, 'nso_interface_type': 'GigabitEthernet', 'oc_sub_interface_place_counter': 0},
    'Vlan': {100: {'oc_interface_index': 10, 'nso_interface_index': 0, 'physical_interface_number': '100',
    'oc_sub_interface_number': 0, 'nso_interface_type': 'Vlan', 'oc_sub_interface_place_counter': 0}}}
    """
    oc_interface_index = 0
    interface_dict = {}
    for interface_type in config_before.get("tailf-ned-cisco-ios:interface", {}):
        if interface_type != "Port-channel-subinterface" and nso_to_oc_interface_types.get(interface_type):
            interface_dict[interface_type] = {}
            nso_old_physical_interface_number = None
            oc_sub_interface_place_counter = 0  # OC interface sub-if place counter
            old_nso_index = 0  # Needed to not increase oc_interface_index when using subinterfaces
            for nso_index, value in enumerate(config_before["tailf-ned-cisco-ios:interface"][interface_type]):
                # Find sub-interface number
                interface_numbering = str(value["name"]).split('.')  # If '.' then number.sub-if
                physical_interface_number = interface_numbering[0]
                # sub-if is 0 unless there is a sub-if number
                oc_sub_interface_number = 0  # Most interfaces don't have a sub-if number
                if len(interface_numbering) > 1:  # If interface has a sub-if number then use that
                    oc_sub_interface_number = int(interface_numbering[1])

                # Are there more than one sub-if?
                # Note - the interface_dict is in order of physical and sub-interfaces
                # because they are organized that way in the NSO config, and we are iterating over NSO's config
                if physical_interface_number == nso_old_physical_interface_number:  # Means there is at least one sub-if
                    oc_sub_interface_place_counter += 1
                else:
                    oc_sub_interface_place_counter = 0

                if (nso_old_physical_interface_number == physical_interface_number) and (
                        nso_index == old_nso_index + 1):
                    oc_interface_index -= 1  # The OC interface index is for physical interfaces, if sub-if remove the past increase

                temp = {value["name"]:
                            {"oc_interface_index": oc_interface_index,
                             "nso_interface_index": nso_index,
                             "physical_interface_number": physical_interface_number,
                             "oc_sub_interface_number": oc_sub_interface_number,
                             "nso_interface_type": interface_type,
                             "oc_sub_interface_place_counter": oc_sub_interface_place_counter}
                        }
                interface_dict[interface_type].update(temp)

                if oc_sub_interface_place_counter == 0:
                    openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"].append(
                        {"openconfig-interfaces:name": f"{interface_type}{physical_interface_number}",
                         "openconfig-interfaces:config": {
                             "openconfig-interfaces:name": f"{interface_type}{physical_interface_number}"}})
                    old_nso_index = nso_index
                    oc_interface_index += 1  # Do not increase oc_interface_index for sub-interfaces
                nso_old_physical_interface_number = physical_interface_number
            # When finished processing sub-ifs, increase oc_interface_index for next main/physical interface
            if oc_sub_interface_number > 0:
                oc_interface_index += 1

        if interface_type == "Port-channel-subinterface" and config_before["tailf-ned-cisco-ios:interface"][
            interface_type].get("Port-channel") and nso_to_oc_interface_types.get(interface_type):
            interface_dict[interface_type] = {}
            oc_sub_interface_place_counter = 0  # OC interface sub-if place counter
            nso_old_physical_interface_number = None
            for nso_index, value in enumerate(
                    config_before["tailf-ned-cisco-ios:interface"]["Port-channel-subinterface"]["Port-channel"]):
                interface_numbering = str(value["name"]).split('.')  # If '.' then number.su-if

                physical_interface_number = interface_numbering[0]
                oc_sub_interface_number = int(interface_numbering[1])
                oc_interface_index = interface_dict["Port-channel"][int(physical_interface_number)][
                    "oc_interface_index"]

                if physical_interface_number == nso_old_physical_interface_number:  # Means there is at least one sub-if
                    oc_sub_interface_place_counter += 1
                else:
                    oc_sub_interface_place_counter = 0
                temp = {value["name"]:
                            {"oc_interface_index": oc_interface_index,
                             "nso_interface_index": nso_index,
                             "physical_interface_number": physical_interface_number,
                             "oc_sub_interface_number": oc_sub_interface_number,
                             "nso_interface_type": "Port-channel-subinterface",
                             "oc_sub_interface_place_counter": oc_sub_interface_place_counter}
                        }
                interface_dict[interface_type].update(temp)
                nso_old_physical_interface_number = physical_interface_number
            oc_interface_index += 1
    # pprint.pprint(interface_dict)
    return interface_dict


def configure_switched_vlan(nso_before_interface: dict, nso_leftover_interface: dict,
                            openconfig_interface: dict) -> None:
    """Configure L2 interfaces: TRUNK and ACCESS"""
    openconfig_interface.update(
        {"openconfig-vlan:switched-vlan": {"openconfig-vlan:config": {}}})
    # Mode ACCESS
    if type(nso_before_interface["switchport"].get("mode", {}).get("access")) is dict:
        openconfig_interface["openconfig-vlan:switched-vlan"][
            "openconfig-vlan:config"]["openconfig-vlan:interface-mode"] = "ACCESS"
        del nso_leftover_interface["switchport"]["mode"]
        openconfig_interface["openconfig-vlan:switched-vlan"][
            "openconfig-vlan:config"]["openconfig-vlan:access-vlan"] = \
            nso_before_interface["switchport"].get("access", {}).get("vlan")
        del nso_leftover_interface["switchport"]["access"]
    # Mode TRUNK
    if (type(nso_before_interface["switchport"].get("mode", {}).get("trunk")) is dict) and (
            nso_before_interface["switchport"].get("trunk", {}).get("encapsulation") == "dot1q"):
        openconfig_interface["openconfig-vlan:switched-vlan"][
            "openconfig-vlan:config"]["openconfig-vlan:interface-mode"] = "TRUNK"
        del nso_leftover_interface["switchport"]["mode"]
        del nso_leftover_interface["switchport"]["trunk"]["encapsulation"]
        if nso_before_interface["switchport"].get("trunk").get("native", {}).get("vlan"):
            openconfig_interface["openconfig-vlan:switched-vlan"][
                "openconfig-vlan:config"]["openconfig-vlan:native-vlan"] = \
                nso_before_interface["switchport"]["trunk"].get("native", {}).get("vlan")
            del nso_leftover_interface["switchport"]["trunk"]["native"]
        if nso_before_interface["switchport"].get("trunk").get("allowed", {}).get("vlan", {}).get("vlans"):
            openconfig_interface["openconfig-vlan:switched-vlan"][
                "openconfig-vlan:config"]["openconfig-vlan:trunk-vlans"] = \
                nso_before_interface["switchport"].get("trunk").get("allowed", {}).get("vlan", {}).get("vlans")
            del nso_leftover_interface["switchport"]["trunk"]["allowed"]


def xe_configure_ipv4_interface(nso_before_interface: dict, nso_leftover_interface: dict,
                                openconfig_interface: dict) -> None:
    """IPv4 interface configurations"""
    oc_ipv4_structure = {"openconfig-if-ip:ipv4": {"openconfig-if-ip:addresses": {"openconfig-if-ip:address": []},
                                                   "openconfig-if-ip:config": {}}}
    if (nso_before_interface.get("ip") and not nso_before_interface.get("ip", {}).get("no-address")) or (
    nso_before_interface.get("vrrp")):
        openconfig_interface.update(oc_ipv4_structure)
        ipv4_address_structure = {}
        if (nso_before_interface["ip"].get(
                "address", {}).get("primary", {}).get("address") and nso_before_interface["ip"].get("address", {}).get(
            "primary", {}).get("mask")):
            prefix = ipaddress.IPv4Network(
                f'{nso_before_interface["ip"].get("address", {}).get("primary", {}).get("address")}/{nso_before_interface["ip"].get("address", {}).get("primary", {}).get("mask")}',
                strict=False)
            mask = prefix.prefixlen
            ip = nso_before_interface["ip"].get("address", {}).get("primary", {}).get("address")
            del nso_leftover_interface["ip"]["address"]["primary"]
            ipv4_address_structure.update({"openconfig-if-ip:ip": ip,
                                           "openconfig-if-ip:config": {"openconfig-if-ip:ip": ip,
                                                                       "openconfig-if-ip:prefix-length": mask}})
        if len(ipv4_address_structure) > 0:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:addresses"][
                "openconfig-if-ip:address"].append(ipv4_address_structure)
        if type(nso_before_interface["ip"].get(
                "address", {}).get("dhcp", "")) is dict:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip:dhcp-client"] = True
            del \
                nso_before_interface["ip"]["address"]
        else:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip:dhcp-client"] = False
        # VRRP
        if nso_before_interface.get("vrrp"):
            vrrp_dict = xe_configure_vrrp_interfaces(nso_before_interface, nso_leftover_interface)
            ipv4_address_structure.update(vrrp_dict)
        # HSRP
        if nso_before_interface.get("standby", {}).get("standby-list"):
            hsrp_dict = xe_configure_hsrp_interfaces(nso_before_interface, nso_leftover_interface)
            ipv4_address_structure.update(hsrp_dict)
        # IP MTU
        if nso_before_interface.get("ip", {}).get("mtu"):
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip:mtu"] = nso_before_interface.get("ip", {}).get("mtu")

            del nso_leftover_interface["ip"]["mtu"]
        # adjust TCP MSS
        if nso_before_interface.get("ip", {}).get("tcp", {}).get("adjust-mss"):
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:tcp-adjust-mss"] = nso_before_interface["ip"]["tcp"]["adjust-mss"]

            del nso_leftover_interface["ip"]["tcp"]["adjust-mss"]
        # IP redirects
        if nso_before_interface.get("ip", {}).get("redirects"):
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:redirects"] = True
            del nso_leftover_interface["ip"]["redirects"]
        elif nso_before_interface.get("ip", {}).get("redirects") is False:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:redirects"] = False
            del nso_leftover_interface["ip"]["redirects"]
        # IP unreachables
        if nso_before_interface.get("ip", {}).get("unreachables"):
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:unreachables"] = True
            del nso_leftover_interface["ip"]["unreachables"]
        elif nso_before_interface.get("ip", {}).get(
                "unreachables") is False:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:unreachables"] = False
            del nso_leftover_interface["ip"]["unreachables"]
        # Proxy-ARP
        if nso_before_interface.get("ip", {}).get("proxy-arp"):
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:proxy-arp"] = {
                "openconfig-if-ip:config": {"openconfig-if-ip:mode": "REMOTE_ONLY"}}
            del nso_leftover_interface["ip"]["proxy-arp"]
        elif nso_before_interface.get("ip", {}).get("proxy-arp") is False:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:proxy-arp"] = {
                "openconfig-if-ip:config": {"openconfig-if-ip:mode": "DISABLE"}}
            del nso_leftover_interface["ip"]["proxy-arp"]
        # reply-mask
        if nso_before_interface.get("ip", {}).get("mask-reply"):
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:mask-reply"] = True
            del nso_leftover_interface["ip"]["mask-reply"]
        # NAT interface
        if nso_before_interface.get("ip", {}).get("nat", {}).get("inside"):
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"]["openconfig-if-ip-mdd-ext:nat"] = {
                "openconfig-if-ip-mdd-ext:nat-choice": "inside"}
            del nso_leftover_interface["ip"]["nat"]["inside"]
        elif nso_before_interface.get("ip", {}).get("nat", {}).get("outside"):
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"]["openconfig-if-ip-mdd-ext:nat"] = {
                "openconfig-if-ip-mdd-ext:nat-choice": "outside"}
            del nso_leftover_interface["ip"]["nat"]["outside"]


def configure_software_loopback(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """Configure Loopbacks"""
    for interface_directory in interface_data.values():
        path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                   interface_directory["oc_interface_index"], "openconfig-interfaces:subinterfaces",
                   "openconfig-interfaces:subinterface", interface_directory["oc_sub_interface_place_counter"]]
        path_nso = ["tailf-ned-cisco-ios:interface", interface_directory["nso_interface_type"],
                    interface_directory["nso_interface_index"]]
        openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)
        nso_before_interface = return_nested_dict(config_before, path_nso)
        nso_leftover_interface = return_nested_dict(config_leftover, path_nso)

        xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface)
        xe_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface)


def configure_software_vasi(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """Configure VASI"""
    for interface_directory in interface_data.values():
        path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                   interface_directory["oc_interface_index"], "openconfig-interfaces:subinterfaces",
                   "openconfig-interfaces:subinterface", interface_directory["oc_sub_interface_place_counter"]]
        path_nso = ["tailf-ned-cisco-ios:interface", interface_directory["nso_interface_type"],
                    interface_directory["nso_interface_index"]]
        openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)
        nso_before_interface = return_nested_dict(config_before, path_nso)
        nso_leftover_interface = return_nested_dict(config_leftover, path_nso)

        xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface)
        xe_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface)


def configure_software_l3ipvlan(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """Configure routed VLANs"""
    for interface_directory in interface_data.values():
        path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                   interface_directory["oc_interface_index"]]
        path_nso = ["tailf-ned-cisco-ios:interface", interface_directory["nso_interface_type"],
                    interface_directory["nso_interface_index"]]
        openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)
        nso_before_interface = return_nested_dict(config_before, path_nso)
        nso_leftover_interface = return_nested_dict(config_leftover, path_nso)

        xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface)
        vlan = nso_before_interface.get("name")

        openconfig_interface.update(
            {"openconfig-vlan:routed-vlan": {"openconfig-vlan:config": {"openconfig-vlan:vlan": vlan}}})

        path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                   interface_directory["oc_interface_index"], "openconfig-vlan:routed-vlan"]
        openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)
        xe_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface)


def configure_port_channel(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """Configure LACP port-channel"""
    for interface_directory in interface_data.values():
        # Configure port-channel interface
        if interface_directory["nso_interface_type"] == "Port-channel":
            path_oc_physical = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                                interface_directory["oc_interface_index"]]
            openconfig_interface_physical = return_nested_dict(openconfig_interfaces, path_oc_physical)
            path_nso_physical = ["tailf-ned-cisco-ios:interface", interface_directory["nso_interface_type"],
                                 interface_directory["nso_interface_index"]]
            nso_before_interface = return_nested_dict(config_before, path_nso_physical)
            nso_leftover_interface = return_nested_dict(config_leftover, path_nso_physical)
            xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_physical)
            openconfig_interface_physical.update({"openconfig-if-aggregate:aggregation": {
                "openconfig-if-aggregate:config": {"openconfig-if-aggregate:lag-type": "LACP"}}})
            path_oc_agg = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                           interface_directory["oc_interface_index"], "openconfig-if-aggregate:aggregation"]
            openconfig_interface_agg = return_nested_dict(openconfig_interfaces, path_oc_agg)
            if nso_before_interface.get("switchport"):
                configure_switched_vlan(nso_before_interface, nso_leftover_interface, openconfig_interface_agg)
            xe_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface_agg)
        # Configure port-channel sub-interfaces
        if interface_directory["nso_interface_type"] == "Port-channel-subinterface":
            path_nso_subif = ["tailf-ned-cisco-ios:interface", "Port-channel-subinterface", "Port-channel",
                              interface_directory["nso_interface_index"]]
            nso_before_interface = return_nested_dict(config_before, path_nso_subif)
            nso_leftover_interface = return_nested_dict(config_leftover, path_nso_subif)
            path_oc_physical = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                                interface_directory["oc_interface_index"]]
            openconfig_interface_physical = return_nested_dict(openconfig_interfaces, path_oc_physical)
            if not openconfig_interface_physical.get("openconfig-interfaces:subinterfaces"):
                openconfig_interface_physical.update(
                    {"openconfig-interfaces:subinterfaces": {"openconfig-interfaces:subinterface": []}})

            openconfig_interface_physical["openconfig-interfaces:subinterfaces"][
                "openconfig-interfaces:subinterface"].append(
                {"openconfig-interfaces:index": interface_directory["oc_sub_interface_number"],
                 "openconfig-interfaces:config": {
                     "openconfig-interfaces:index": interface_directory[
                         "oc_sub_interface_number"]}})

            path_oc_subif = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                             interface_directory["oc_interface_index"], "openconfig-interfaces:subinterfaces",
                             "openconfig-interfaces:subinterface", interface_directory["oc_sub_interface_place_counter"]]

            openconfig_interface_subif = return_nested_dict(openconfig_interfaces, path_oc_subif)

            xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_subif)
            xe_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface_subif)


def configure_software_tunnel(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """Configure GRE Tunnel"""
    for interface_directory in interface_data.values():
        # Configure tunnel interface
        path_oc_physical = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                            interface_directory["oc_interface_index"]]
        openconfig_interface_physical = return_nested_dict(openconfig_interfaces, path_oc_physical)
        path_nso_physical = ["tailf-ned-cisco-ios:interface", interface_directory["nso_interface_type"],
                             interface_directory["nso_interface_index"]]
        nso_before_interface = return_nested_dict(config_before, path_nso_physical)
        nso_leftover_interface = return_nested_dict(config_leftover, path_nso_physical)

        xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_physical)

        openconfig_interface_physical["openconfig-if-tunnel:tunnel"] = {"openconfig-if-tunnel:config": {}}
        path_oc_tunnel = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface", interface_directory["oc_interface_index"], "openconfig-if-tunnel:tunnel"]
        openconfig_interface_tunnel = return_nested_dict(openconfig_interfaces, path_oc_tunnel)

        # TODO: Fix prefix issue
        # xe_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface_tunnel)

        # source IP
        if nso_before_interface.get("tunnel", {}).get("source"):
            openconfig_interface_tunnel["openconfig-if-tunnel:config"]["openconfig-if-tunnel:src"] = nso_before_interface.get("tunnel", {}).get("source")
            del nso_leftover_interface["tunnel"]["source"]
        # destination IP
        if nso_before_interface.get("tunnel", {}).get("destination"):
            openconfig_interface_tunnel["openconfig-if-tunnel:config"]["openconfig-if-tunnel:dst"] = nso_before_interface.get("tunnel", {}).get("destination")
            del nso_leftover_interface["tunnel"]["destination"]
        # key
        if nso_before_interface.get("tunnel", {}).get("key"):
            openconfig_interface_tunnel["openconfig-if-tunnel:config"]["openconfig-if-tunnel:gre-key"] = nso_before_interface.get("tunnel", {}).get("key")
            del nso_leftover_interface["tunnel"]["key"]
        # PMTUD
        if type(nso_before_interface.get("tunnel", {}).get("path-mtu-discovery", "")) is dict:
            openconfig_interface_tunnel["openconfig-if-tunnel:config"]["openconfig-if-tunnel-ext:tunnel-path-mtu-discovery"] = True
            del nso_leftover_interface["tunnel"]["path-mtu-discovery"]
        # keepalives
        if nso_before_interface.get("keepalive-period-retries", {}).get("keepalive", {}).get("period") and nso_before_interface.get("keepalive-period-retries", {}).get("keepalive", {}).get("retries"):
            openconfig_interface_tunnel["openconfig-if-tunnel:config"]["openconfig-if-tunnel-ext:keepalives"] = {"openconfig-if-tunnel-ext:period": nso_before_interface.get("keepalive-period-retries", {}).get("keepalive", {}).get("period"), "openconfig-if-tunnel-ext:retries": nso_before_interface.get("keepalive-period-retries", {}).get("keepalive", {}).get("retries")}
            del nso_leftover_interface["keepalive-period-retries"]


def xe_interface_config(nso_before_interface: dict, nso_leftover_interface: dict, openconfig_interface: dict) -> None:
    """
    Configure basic interface functions, i.e. description, shutdown, MTU
    Note - subinterface 0 values are removed from config leftover during configuration of the physical interface
    """
    # Description
    if nso_before_interface.get('description'):
        openconfig_interface["openconfig-interfaces:config"][
            'openconfig-interfaces:description'] = nso_before_interface.get('description')
        try:
            del nso_leftover_interface["description"]
        except:
            pass
    # Shutdown
    if nso_before_interface.get('shutdown'):
        openconfig_interface["openconfig-interfaces:config"]["openconfig-interfaces:enabled"] = False
        try:
            del nso_leftover_interface["shutdown"]
        except:
            pass
    else:
        openconfig_interface["openconfig-interfaces:config"]["openconfig-interfaces:enabled"] = True
    # MTU
    if nso_before_interface.get("mtu"):
        openconfig_interface["openconfig-interfaces:config"]["openconfig-interfaces:mtu"] = nso_before_interface.get(
            "mtu")
        try:
            del nso_leftover_interface["mtu"]
        except:
            pass


def xe_interface_hold_time(config_before: dict, config_leftover: dict, v: dict) -> None:
    """Configure physical interface hold-time (carrier-delay)"""
    if config_before["tailf-ned-cisco-ios:interface"][v["nso_interface_type"]][v["nso_interface_index"]].get(
            "carrier-delay", {}).get("msec"):
        openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"][
            v["oc_interface_index"]]["openconfig-interfaces:hold-time"] = {"openconfig-interfaces:config": {
            "openconfig-interfaces:down": config_before["tailf-ned-cisco-ios:interface"][v["nso_interface_type"]][
                v["nso_interface_index"]].get("carrier-delay", {}).get("msec")}}
        del config_leftover["tailf-ned-cisco-ios:interface"][v["nso_interface_type"]][v["nso_interface_index"]][
            "carrier-delay"]["msec"]


def xe_configure_vrrp_interfaces(nso_before_interface: dict, nso_leftover_interface: dict) -> dict:
    """Configure VRRP"""
    service_vrrp = {"openconfig-if-ip:vrrp": {"openconfig-if-ip:vrrp-group": []}}
    for number, group in enumerate(nso_before_interface.get("vrrp")):
        if group.get("id"):
            # Group
            service_vrrp_group = {"openconfig-if-ip:virtual-router-id": group.get("id"),
                                  "openconfig-if-ip:config": {"openconfig-if-ip:virtual-router-id": group.get("id")}}
            del nso_leftover_interface["vrrp"][number]["id"]
            # Preempt delay
            if group.get("preempt", {}).get("delay", {}).get("minimum"):
                service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:preempt-delay"] = group.get("preempt",
                                                                                                            {}).get(
                    "delay", {}).get("minimum")
                del nso_leftover_interface["vrrp"][number]["preempt"]["delay"]
            # Preempt
            if group.get("preempt"):
                service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:preempt"] = True
                del nso_leftover_interface["vrrp"][number]["preempt"]
            # Priority
            if group.get("priority"):
                service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:priority"] = group.get("priority")
                del nso_leftover_interface["vrrp"][number]["priority"]
            # VRRP Address
            if group.get("ip", {}).get("address"):
                service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:virtual-address"] = []
                service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:virtual-address"].append(
                    group.get("ip", {}).get("address"))
                del nso_leftover_interface["vrrp"][number]["ip"]
            # Timers advertise
            if group.get("timers", {}).get("advertise").get("seconds"):
                service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:advertisement-interval"] = int(
                    group.get("timers", {}).get("advertise").get("seconds")) * 100
                del nso_leftover_interface["vrrp"][number]["timers"]["advertise"]
            service_vrrp["openconfig-if-ip:vrrp"]["openconfig-if-ip:vrrp-group"].append(service_vrrp_group)
    return service_vrrp


def xe_configure_hsrp_interfaces(nso_before_interface: dict, nso_leftover_interface: dict) -> dict:
    """Configure HSRP"""
    service_hsrp = {"openconfig-if-ip-mdd-ext:hsrp": {"openconfig-if-ip-mdd-ext:hsrp-group": []}}
    for number, group in enumerate(nso_before_interface.get("standby", {}).get("standby-list")):
        if group.get("group-number"):
            # Group
            service_hsrp_group = {"openconfig-if-ip-mdd-ext:group-number": group.get("group-number"),
                                  "openconfig-if-ip-mdd-ext:config": {
                                      "openconfig-if-ip-mdd-ext:group-number": group.get("group-number")}}
            del nso_leftover_interface["standby"]["standby-list"][number]["group-number"]
            # Preempt delay
            if group.get("preempt", {}).get("delay", {}).get("minimum"):
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:preempt-delay"] = group.get("preempt",
                                                                                                            {}).get(
                    "delay", {}).get("minimum")
                del nso_leftover_interface["standby"]["standby-list"][number]["preempt"]["delay"]
            # Preempt
            if group.get("preempt"):
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:preempt"] = True
                del nso_leftover_interface["standby"]["standby-list"][number]["preempt"]
            # Priority
            if group.get("priority"):
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:priority"] = group.get("priority")
                del nso_leftover_interface["standby"]["standby-list"][number]["priority"]
            # VRRP Address
            if group.get("ip", {}).get("address"):
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:virtual-address"] = []
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:virtual-address"].append(
                    group.get("ip", {}).get("address"))
                del nso_leftover_interface["standby"]["standby-list"][number]["ip"]
            # Timers
            if group.get("timers", {}).get("hello-interval", {}).get("seconds") and group.get("timers", {}).get(
                    "hold-time", {}).get("seconds"):
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"].update({"openconfig-if-ip-mdd-ext:timers": {
                    "openconfig-if-ip-mdd-ext:hello-interval": int(
                        group.get("timers", {}).get("hello-interval").get("seconds")),
                    "openconfig-if-ip-mdd-ext:holdtime": int(group.get("timers", {}).get("hold-time").get("seconds"))
                }})
                del nso_leftover_interface["standby"]["standby-list"][number]["timers"]["hello-interval"]
                del nso_leftover_interface["standby"]["standby-list"][number]["timers"]["hold-time"]

            service_hsrp["openconfig-if-ip-mdd-ext:hsrp"]["openconfig-if-ip-mdd-ext:hsrp-group"].append(service_hsrp_group)
    return service_hsrp


def configure_csmacd(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """
    Iterate through interface_data
    Call up the config_before["tailf-ned-cisco-ios:interface"][v["nso_interface_type"]][v["nso_interface_index"]]
    Add need OC config to openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"][v["oc_interface_index"]]
    """
    for interface_directory in interface_data.values():
        path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                   interface_directory["oc_interface_index"], "openconfig-interfaces:subinterfaces",
                   "openconfig-interfaces:subinterface", interface_directory["oc_sub_interface_place_counter"]]
        openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)

        path_nso = ["tailf-ned-cisco-ios:interface", interface_directory["nso_interface_type"],
                    interface_directory["nso_interface_index"]]
        nso_before_interface = return_nested_dict(config_before, path_nso)
        nso_leftover_interface = return_nested_dict(config_leftover, path_nso)

        # Configure sub-interface
        xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface)

        path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                   interface_directory["oc_interface_index"]]
        openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)

        # Configure physical interface
        xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface)
        # Configure physical interface hold-time (carrier-delay)
        xe_interface_hold_time(config_before, config_leftover, interface_directory)

        # Configure ethernet settings
        openconfig_interface.update({"openconfig-if-ethernet:ethernet": {"openconfig-if-ethernet:config": {}}})
        if nso_before_interface.get("speed"):
            openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                "openconfig-if-ethernet:port-speed"] = nso_before_interface.get("speed")
            del nso_leftover_interface["speed"]
        if nso_before_interface.get("duplex"):
            openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                "openconfig-if-ethernet:duplex-mode"] = nso_before_interface.get("duplex")
            del nso_leftover_interface["duplex"]
        if nso_before_interface.get("negotiation", {}).get("auto"):
            openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                "openconfig-if-ethernet:auto-negotiate"] = True
            del nso_leftover_interface["negotiation"]["auto"]
        if nso_before_interface.get("flowcontrol", {}).get("receive") == "on":
            openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                "openconfig-if-ethernet:enable-flow-control"] = True
            del nso_leftover_interface["flowcontrol"]["receive"]
        if nso_before_interface.get("mac-address"):
            n_mac = nso_before_interface.get("mac-address")
            openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                "openconfig-interfaces:mac-address"] = f"{n_mac[0:2]}:{n_mac[2:4]}:{n_mac[5:7]}:{n_mac[7:9]}:{n_mac[10:12]}:{n_mac[12:14]}"  # NSO 5254.0014.3427 OC = MM:MM:MM:SS:SS:SS
            del nso_leftover_interface["mac-address"]

        # Is type really a l2vlan?
        if nso_before_interface.get("switchport"):
            openconfig_interface["openconfig-interfaces:config"]["openconfig-interfaces:type"] = "l2vlan"
            path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                       interface_directory["oc_interface_index"], "openconfig-if-ethernet:ethernet"]
            openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)
            configure_switched_vlan(nso_before_interface, nso_leftover_interface, openconfig_interface)
        else:
            path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                       interface_directory["oc_interface_index"], "openconfig-interfaces:subinterfaces",
                       "openconfig-interfaces:subinterface", interface_directory["oc_sub_interface_place_counter"]]
            openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)
            xe_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface)

        # Is interface an LACP member?
        if (nso_before_interface.get("channel-group", {}).get("number")) and (
                nso_before_interface.get("channel-group", {}).get("mode", "") == "active"):
            openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"][
                interface_directory["oc_interface_index"]]["openconfig-if-ethernet:ethernet"][
                "openconfig-if-ethernet:config"][
                "openconfig-if-aggregate:aggregate-id"] = f'Port-channel{str(nso_before_interface.get("channel-group", {}).get("number"))}'
            del nso_leftover_interface["channel-group"]


def xe_interfaces(config_before: dict, config_leftover: dict, interfaces: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig Interfaces Config
    """
    # Identify interface types
    for interface_type in interfaces:
        for interface in interfaces[interface_type]:
            # Assign default interface types
            interfaces[interface_type][interface]["oc_type"] = nso_to_oc_interface_types.get(interface_type, "unsupported")
            openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"][
                interfaces[interface_type][interface]["oc_interface_index"]]["openconfig-interfaces:config"][
                "openconfig-interfaces:type"] = nso_to_oc_interface_types[interface_type]

    for interface_type in interfaces:
        for v in interfaces[interface_type].values():
            if_types_with_subifs = ["ethernetCsmacd", "softwareLoopback", "vasi"]
            if v["oc_type"] in if_types_with_subifs:
                if v["oc_sub_interface_number"] == 0:
                    subif = {"openconfig-interfaces:subinterfaces": {"openconfig-interfaces:subinterface": []}}
                    openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"][
                        v["oc_interface_index"]].update(subif)
                temp = {"openconfig-interfaces:index": v["oc_sub_interface_number"],
                        "openconfig-interfaces:config": {"openconfig-interfaces:index": v["oc_sub_interface_number"]}}
                openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"][
                    v["oc_interface_index"]]["openconfig-interfaces:subinterfaces"][
                    "openconfig-interfaces:subinterface"].append(temp)

    # Configure the interface types
    for interface_type in interfaces:
        if nso_to_oc_interface_types[interface_type] == "ieee8023adLag":
            configure_port_channel(config_before, config_leftover, interfaces[interface_type])
        if nso_to_oc_interface_types[interface_type] == "ethernetCsmacd":
            # can be converted to l2vlan if contains 'switchport'
            configure_csmacd(config_before, config_leftover, interfaces[interface_type])
        if nso_to_oc_interface_types[interface_type] == "softwareLoopback":
            configure_software_loopback(config_before, config_leftover, interfaces[interface_type])
        if nso_to_oc_interface_types[interface_type] == "l3ipvlan":
            configure_software_l3ipvlan(config_before, config_leftover, interfaces[interface_type])
        if nso_to_oc_interface_types[interface_type] == "tunnel":
            configure_software_tunnel(config_before, config_leftover, interfaces[interface_type])
        if nso_to_oc_interface_types[interface_type] == "vasi":
            configure_software_vasi(config_before, config_leftover, interfaces[interface_type])


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
    :return: MDD Openconfig Interfaces configuration: dict
    """

    interfaces = create_interface_dict(before)
    xe_interfaces(before, leftover, interfaces)

    return openconfig_interfaces


if __name__ == '__main__':
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
    main(config_before_dict, config_leftover_dict)

    print(json.dumps(openconfig_interfaces, indent=4))
    with open(f"../{nso_device}_ned_configuration_interfaces.json", "w") as b:
        b.write(json.dumps(config_before_dict, indent=4))
    with open(f"../{nso_device}_ned_configuration_remaining_interfaces.json", "w") as a:
        a.write(json.dumps(config_leftover_dict, indent=4))
    with open(f"../{nso_device}_openconfig_interfaces.json", "w") as o:
        o.write(json.dumps(openconfig_interfaces, indent=4))

    if test == 'True':
        common.test_nso_program_oc(nso_host, nso_username, nso_password, nso_device, openconfig_interfaces)