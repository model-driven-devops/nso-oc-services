#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_interfaces.json, save the
NSO device configuration minus parts replaced by MDD OpenConfig to a file named
{device_name}_ned_configuration_remaining_interfaces.json, and save the MDD OpenConfig configuration to a file named
{nso_device}_openconfig_interfaces.json.

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
import ipaddress

interfaces_notes = []

openconfig_interfaces = {
    "openconfig-interfaces:interfaces": {
        "openconfig-interfaces:interface": [
        ]
    }
}

nso_to_oc_interface_types = {
    "FastEthernet": "ethernetCsmacd",
    "FastEthernet-subinterface": "ethernetCsmacd",
    "FortyGigE": "ethernetCsmacd",
    "FortyGigE-subinterface": "ethernetCsmacd",
    "FiftyGigE": "ethernetCsmacd",
    "FiftyGigE-subinterface": "ethernetCsmacd",
    "FourHundredGigE": "ethernetCsmacd",
    "FourHundredGigE-subinterface": "ethernetCsmacd",
    "GigabitEthernet": "ethernetCsmacd",
    "GigabitEthernet-subinterface": "ethernetCsmacd",
    "HundredGigE": "ethernetCsmacd",
    "HundredGigE-subinterface": "ethernetCsmacd",
    "Loopback": "softwareLoopback",
    "tunnel-ip": "tunnel",
    "TenGigE": "ethernetCsmacd",
    "TenGigE-subinterface": "ethernetCsmacd",
    "TwentyFiveGigE": "ethernetCsmacd",
    "TwentyFiveGigE-subinterface": "ethernetCsmacd",
    "TwoHundredGigE": "ethernetCsmacd",
    "TwoHundredGigE-subinterface": "ethernetCsmacd",
    "Vlan": "l3ipvlan",
    "Bundle-Ether": "ieee8023adLag",
    "Bundle-Ether-subinterface": "ieee8023adLag"
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

    def index_subinterfaces(interface_type, nso_old_physical_interface_number):
        interface_dict[interface_type] = {}
        oc_sub_interface_place_counter = 0  # OC interface sub-if place counter

        for nso_index, value in enumerate(
                config_before["tailf-ned-cisco-ios-xr:interface"][interface_type][
                    interface_type.replace("-subinterface", "")]):
            interface_numbering = str(value["id"]).split('.')  # If '.' then number.su-if

            physical_interface_number = interface_numbering[0]
            oc_sub_interface_number = int(interface_numbering[1])
            oc_interface_index = \
            interface_dict[interface_type.replace("-subinterface", "")][physical_interface_number][
                "oc_interface_index"]

            if oc_sub_interface_number != 0 and (nso_old_physical_interface_number != physical_interface_number):
                oc_sub_interface_place_counter = 1
            elif oc_sub_interface_number != 0 and (nso_old_physical_interface_number == physical_interface_number):
                oc_sub_interface_place_counter += 1
            temp = {value["id"]:
                        {"oc_interface_index": oc_interface_index,
                         "nso_interface_index": nso_index,
                         "physical_interface_number": physical_interface_number,
                         "oc_sub_interface_number": oc_sub_interface_number,
                         "nso_interface_type": interface_type,
                         "oc_sub_interface_place_counter": oc_sub_interface_place_counter}
                    }
            interface_dict[interface_type].update(temp)
            nso_old_physical_interface_number = physical_interface_number
        oc_interface_index += 1

    oc_interface_index = 0
    interface_dict = {}
    for interface_type in config_before.get("tailf-ned-cisco-ios-xr:interface", {}):
        nso_old_physical_interface_number = None
        if "-subinterface" not in interface_type and nso_to_oc_interface_types.get(interface_type):
            interface_dict[interface_type] = {}
            oc_sub_interface_place_counter = 0  # OC interface sub-if place counter
            old_nso_index = 0  # Needed to not increase oc_interface_index when using subinterfaces
            for nso_index, value in enumerate(config_before["tailf-ned-cisco-ios-xr:interface"][interface_type]):
                # Find sub-interface number
                interface_numbering = str(value["id"]).split('.')  # If '.' then number.sub-if
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

                temp = {str(value["id"]):
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
                    oc_interface_index += 1  # Do not increase oc_interface_index for sub-interfaces
                old_nso_index = nso_index
                nso_old_physical_interface_number = physical_interface_number
                # When finished processing sub-ifs, increase oc_interface_index for next main/physical interface
                if oc_sub_interface_number > 0:
                    oc_interface_index += 1

        if "-subinterface" in interface_type and nso_to_oc_interface_types.get(interface_type):
            index_subinterfaces(interface_type, nso_old_physical_interface_number)
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


def xr_configure_ipv4_interface(nso_before_interface: dict, nso_leftover_interface: dict,
                                openconfig_interface: dict) -> None:
    """IPv4 interface configurations"""
    oc_ipv4_structure = {"openconfig-if-ip:ipv4": {"openconfig-if-ip:addresses": {"openconfig-if-ip:address": []},
                                                   "openconfig-if-ip:config": {}}}
    if (nso_before_interface.get("ipv4") and not nso_before_interface.get("ipv4", {}).get("no-address")) or (
            nso_before_interface.get("vrrp")):
        openconfig_interface.update(oc_ipv4_structure)
        ipv4_address_structure = {}
        if (nso_before_interface["ipv4"].get("address", {}).get("ip") and nso_before_interface["ipv4"].get("address",
                                                                                                           {}).get(
                "mask")):
            prefix = ipaddress.IPv4Network(
                f'{nso_before_interface["ipv4"].get("address", {}).get("ip")}/{nso_before_interface["ipv4"].get("address", {}).get("mask")}',
                strict=False)
            mask = prefix.prefixlen
            ip = nso_before_interface["ipv4"].get("address", {}).get("ip")
            del nso_leftover_interface["ipv4"]["address"]["ip"]
            ipv4_address_structure.update({"openconfig-if-ip:ip": ip,
                                           "openconfig-if-ip:config": {"openconfig-if-ip:ip": ip,
                                                                       "openconfig-if-ip:prefix-length": mask}})
        if len(ipv4_address_structure) > 0:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:addresses"][
                "openconfig-if-ip:address"].append(ipv4_address_structure)
        if type(nso_before_interface["ipv4"].get(
                "address-dhcp", {}).get("address", {}).get("dhcp", "")) is list:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip:dhcp-client"] = True
            del \
                nso_before_interface["ipv4"]["address-dhcp"]
        else:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip:dhcp-client"] = False
        # IP MTU
        if nso_before_interface.get("ipv4", {}).get("mtu"):
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip:mtu"] = nso_before_interface.get("ipv4", {}).get("mtu")

            del nso_leftover_interface["ipv4"]["mtu"]
        # # adjust TCP MSS  TODO CML testing issue
        # if nso_before_interface.get("ipv4", {}).get("tcp", {}).get("adjust-mss"):
        #     openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
        #         "openconfig-if-ip-mdd-ext:tcp-adjust-mss"] = nso_before_interface["ipv4"]["tcp"]["adjust-mss"]
        #
        #     del nso_leftover_interface["ipv4"]["tcp"]["adjust-mss"]
        # IP redirects
        if type(nso_before_interface.get("ipv4", {}).get("redirects", "")) is list:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:redirects"] = True
            del nso_leftover_interface["ipv4"]["redirects"]
        else:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:redirects"] = False
        # IP unreachables
        if type(nso_before_interface.get("ipv4", {}).get("unreachables", {}).get("disable", "")) is list:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:unreachables"] = False
            del nso_leftover_interface["ipv4"]["unreachables"]
        else:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:unreachables"] = True
        # Proxy-ARP
        if type(nso_before_interface.get("proxy-arp", "")) is list:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:proxy-arp"] = {
                "openconfig-if-ip:config": {"openconfig-if-ip:mode": "REMOTE_ONLY"}}
            del nso_leftover_interface["proxy-arp"]
        else:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:proxy-arp"] = {
                "openconfig-if-ip:config": {"openconfig-if-ip:mode": "DISABLE"}}
        # reply-mask
        if type(nso_before_interface.get("ipv4", {}).get("mask-reply", "")) is list:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:mask-reply"] = True
            del nso_leftover_interface["ipv4"]["mask-reply"]
        else:
            openconfig_interface["openconfig-if-ip:ipv4"]["openconfig-if-ip:config"][
                "openconfig-if-ip-mdd-ext:mask-reply"] = False


def xr_configure_tunnel_ipv4_interface(nso_before_interface: dict, nso_leftover_interface: dict,
                                       openconfig_interface: dict) -> None:
    """Tunnel IPv4 interface configurations"""
    oc_ipv4_structure = {
        "openconfig-if-tunnel:ipv4": {"openconfig-if-tunnel:addresses": {"openconfig-if-tunnel:address": []},
                                      "openconfig-if-tunnel:config": {}}}
    if nso_before_interface.get("ipv4") and not nso_before_interface.get("ipv4", {}).get("no-address"):
        openconfig_interface.update(oc_ipv4_structure)
        ipv4_address_structure = {}
        if (nso_before_interface["ipv4"].get(
                "address", {}).get("ip") and nso_before_interface["ipv4"].get("address", {}).get("mask")):
            prefix = ipaddress.IPv4Network(
                f'{nso_before_interface["ipv4"].get("address", {}).get("ip")}/{nso_before_interface["ipv4"].get("address", {}).get("mask")}',
                strict=False)
            mask = prefix.prefixlen
            ip = nso_before_interface["ipv4"].get("address", {}).get("ip")
            del nso_leftover_interface["ipv4"]["address"]["ip"]
            del nso_leftover_interface["ipv4"]["address"]["mask"]
            ipv4_address_structure.update({"openconfig-if-tunnel:ip": ip,
                                           "openconfig-if-tunnel:config": {"openconfig-if-tunnel:ip": ip,
                                                                           "openconfig-if-tunnel:prefix-length": mask}})
        if len(ipv4_address_structure) > 0:
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:addresses"][
                "openconfig-if-tunnel:address"].append(ipv4_address_structure)

        # IP MTU
        if nso_before_interface.get("ipv4", {}).get("mtu"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-tunnel:mtu"] = nso_before_interface.get("ipv4", {}).get("mtu")
            del nso_leftover_interface["ipv4"]["mtu"]
        # IP redirects
        if nso_before_interface.get("ipv4", {}).get("redirects"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:redirects"] = True
            del nso_leftover_interface["ipv4"]["redirects"]
        elif nso_before_interface.get("ipv4", {}).get("redirects") is False:
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:redirects"] = False
            del nso_leftover_interface["ipv4"]["redirects"]
        # IP unreachables
        if nso_before_interface.get("ipv4", {}).get("unreachables"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:unreachables"] = True
            del nso_leftover_interface["ipv4"]["unreachables"]
        elif nso_before_interface.get("ipv4", {}).get(
                "unreachables") is False:
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:unreachables"] = False
            del nso_leftover_interface["ipv4"]["unreachables"]
        # Proxy-ARP
        if nso_before_interface.get("ipv4", {}).get("proxy-arp"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:proxy-arp"] = {
                "openconfig-if-tunnel:config": {"openconfig-if-tunnel:mode": "REMOTE_ONLY"}}
            del nso_leftover_interface["ipv4"]["proxy-arp"]
        elif nso_before_interface.get("ipv4", {}).get("proxy-arp") is False:
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:proxy-arp"] = {
                "openconfig-if-tunnel:config": {"openconfig-if-tunnel:mode": "DISABLE"}}
            del nso_leftover_interface["ipv4"]["proxy-arp"]
        # reply-mask
        if nso_before_interface.get("ipv4", {}).get("mask-reply"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:mask-reply"] = True
            del nso_leftover_interface["ipv4"]["mask-reply"]


def configure_software_loopback(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """Configure Loopbacks"""
    for interface_directory in interface_data.values():
        path_oc_sub_if = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                          interface_directory["oc_interface_index"], "openconfig-interfaces:subinterfaces",
                          "openconfig-interfaces:subinterface", interface_directory["oc_sub_interface_place_counter"]]
        path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                   interface_directory["oc_interface_index"]]
        path_nso = ["tailf-ned-cisco-ios-xr:interface", interface_directory["nso_interface_type"],
                    interface_directory["nso_interface_index"]]
        openconfig_interface_sub_if = return_nested_dict(openconfig_interfaces, path_oc_sub_if)
        openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)
        nso_before_interface = return_nested_dict(config_before, path_nso)
        nso_leftover_interface = return_nested_dict(config_leftover, path_nso)

        # Main Interface
        xr_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface)
        # Sub Interface
        xr_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_sub_if)
        xr_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface_sub_if)


def configure_software_l3ipvlan(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """Configure routed VLANs"""
    for interface_directory in interface_data.values():
        path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                   interface_directory["oc_interface_index"]]
        path_nso = ["tailf-ned-cisco-ios-xr:interface", interface_directory["nso_interface_type"],
                    interface_directory["nso_interface_index"]]
        openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)
        nso_before_interface = return_nested_dict(config_before, path_nso)
        nso_leftover_interface = return_nested_dict(config_leftover, path_nso)

        xr_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface)
        vlan = nso_before_interface.get("name")

        openconfig_interface.update(
            {"openconfig-vlan:routed-vlan": {"openconfig-vlan:config": {"openconfig-vlan:vlan": vlan}}})

        path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                   interface_directory["oc_interface_index"], "openconfig-vlan:routed-vlan"]
        openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)
        xr_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface)


def configure_port_channel(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """Configure LACP port-channel"""
    for interface_directory in interface_data.values():
        # Configure port-channel interface
        if interface_directory["nso_interface_type"] == "Bundle-Ether":
            path_oc_physical = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                                interface_directory["oc_interface_index"]]
            openconfig_interface_physical = return_nested_dict(openconfig_interfaces, path_oc_physical)
            path_nso_physical = ["tailf-ned-cisco-ios-xr:interface", interface_directory["nso_interface_type"],
                                 interface_directory["nso_interface_index"]]
            nso_before_interface = return_nested_dict(config_before, path_nso_physical)
            nso_leftover_interface = return_nested_dict(config_leftover, path_nso_physical)
            xr_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_physical)
            openconfig_interface_physical.update({"openconfig-if-aggregate:aggregation": {
                "openconfig-if-aggregate:config": {"openconfig-if-aggregate:lag-type": "LACP"}}})
            path_oc_agg = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                           interface_directory["oc_interface_index"], "openconfig-if-aggregate:aggregation"]
            openconfig_interface_agg = return_nested_dict(openconfig_interfaces, path_oc_agg)
            if nso_before_interface.get("switchport"):
                configure_switched_vlan(nso_before_interface, nso_leftover_interface, openconfig_interface_agg)
            xr_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface_agg)
        # Configure port-channel sub-interfaces
        if interface_directory["nso_interface_type"] == "Bundle-Ether-subinterface":
            path_nso_subif = ["tailf-ned-cisco-ios-xr:interface", "Bundle-Ether-subinterface", "Bundle-Ether",
                              interface_directory["nso_interface_index"]]
            nso_before_interface = return_nested_dict(config_before, path_nso_subif)
            nso_leftover_interface = return_nested_dict(config_leftover, path_nso_subif)

            path_oc_subif = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                             interface_directory["oc_interface_index"], "openconfig-interfaces:subinterfaces",
                             "openconfig-interfaces:subinterface",
                             interface_directory["oc_sub_interface_place_counter"]]

            openconfig_interface_subif = return_nested_dict(openconfig_interfaces, path_oc_subif)

            xr_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_subif, True)
            xr_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface_subif)

            # Add vlan-id for sub-if
            if nso_before_interface.get("encapsulation", {}).get("dot1q", {}).get("vlan-id"):
                openconfig_interface_subif.update({"openconfig-vlan:vlan": {"openconfig-vlan:config": {
                    "openconfig-vlan:vlan-id": nso_before_interface["encapsulation"]["dot1q"]["vlan-id"][0]}}})


def configure_csmacd(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """Configure CSMACD"""
    for interface_directory in interface_data.values():
        # Configure main interface
        if "-subinterface" not in interface_directory["nso_interface_type"]:
            path_oc_sub_if = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                              interface_directory["oc_interface_index"], "openconfig-interfaces:subinterfaces",
                              "openconfig-interfaces:subinterface",
                              interface_directory["oc_sub_interface_place_counter"]]
            openconfig_interface_sub_if = return_nested_dict(openconfig_interfaces, path_oc_sub_if)
            path_nso = ["tailf-ned-cisco-ios-xr:interface", interface_directory["nso_interface_type"],
                        interface_directory["nso_interface_index"]]
            nso_before_interface = return_nested_dict(config_before, path_nso)
            nso_leftover_interface = return_nested_dict(config_leftover, path_nso)

            # Configure sub-interface
            xr_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_sub_if, True)

            path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                       interface_directory["oc_interface_index"]]
            openconfig_interface_physical = return_nested_dict(openconfig_interfaces, path_oc)

            # Configure physical interface
            xr_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_physical)
            # Configure physical interface hold-time (carrier-delay)
            xr_interface_hold_time(config_before, config_leftover, interface_directory)

            # Configure ethernet settings
            openconfig_interface_physical.update(
                {"openconfig-if-ethernet:ethernet": {"openconfig-if-ethernet:config": {}}})
            if nso_before_interface.get("speed"):
                openconfig_interface_physical["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                    "openconfig-if-ethernet:port-speed"] = nso_before_interface.get("speed")
                del nso_leftover_interface["speed"]
            if nso_before_interface.get("duplex"):
                openconfig_interface_physical["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                    "openconfig-if-ethernet:duplex-mode"] = nso_before_interface.get("duplex")
                del nso_leftover_interface["duplex"]
            if nso_before_interface.get("negotiation", {}).get("auto"):
                openconfig_interface_physical["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                    "openconfig-if-ethernet:auto-negotiate"] = True
                del nso_leftover_interface["negotiation"]["auto"]
            if nso_before_interface.get("flowcontrol", {}).get("receive") == "on":
                openconfig_interface_physical["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                    "openconfig-if-ethernet:enable-flow-control"] = True
                del nso_leftover_interface["flowcontrol"]["receive"]
            if nso_before_interface.get("mac-address"):
                n_mac = nso_before_interface.get("mac-address")
                openconfig_interface_physical["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                    "openconfig-interfaces:mac-address"] = f"{n_mac[0:2]}:{n_mac[2:4]}:{n_mac[5:7]}:{n_mac[7:9]}:{n_mac[10:12]}:{n_mac[12:14]}"  # NSO 5254.0014.3427 OC = MM:MM:MM:SS:SS:SS
                del nso_leftover_interface["mac-address"]

            # Is type really a l2vlan?
            if nso_before_interface.get("switchport"):
                configure_switched_vlan(nso_before_interface, nso_leftover_interface, openconfig_interface_physical)
            path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                       interface_directory["oc_interface_index"], "openconfig-interfaces:subinterfaces",
                       "openconfig-interfaces:subinterface", interface_directory["oc_sub_interface_place_counter"]]
            openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)
            xr_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface)
            # Is interface an LACP member?
            if (nso_before_interface.get("channel-group", {}).get("number")) and (
                    nso_before_interface.get("channel-group", {}).get("mode", "") == "active"):
                openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"][
                    interface_directory["oc_interface_index"]]["openconfig-if-ethernet:ethernet"][
                    "openconfig-if-ethernet:config"][
                    "openconfig-if-aggregate:aggregate-id"] = f'Port-channel{str(nso_before_interface.get("channel-group", {}).get("number"))}'
                del nso_leftover_interface["channel-group"]

        # Configure sub-interfaces
        if "-subinterface" in interface_directory["nso_interface_type"]:
            path_nso_subif = ["tailf-ned-cisco-ios-xr:interface", interface_directory["nso_interface_type"],
                              interface_directory["nso_interface_type"].replace("-subinterface", ""),
                              interface_directory["nso_interface_index"]]
            nso_before_interface = return_nested_dict(config_before, path_nso_subif)
            nso_leftover_interface = return_nested_dict(config_leftover, path_nso_subif)

            path_oc_subif = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                             interface_directory["oc_interface_index"], "openconfig-interfaces:subinterfaces",
                             "openconfig-interfaces:subinterface",
                             interface_directory["oc_sub_interface_place_counter"]]

            openconfig_interface_subif = return_nested_dict(openconfig_interfaces, path_oc_subif)

            xr_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_subif, True)
            xr_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface_subif)

            if nso_before_interface.get("encapsulation", {}).get("dot1q", {}).get("vlan-id"):
                openconfig_interface_subif.update({"openconfig-vlan:vlan": {"openconfig-vlan:config": {
                    "openconfig-vlan:vlan-id": nso_before_interface["encapsulation"]["dot1q"]["vlan-id"][0]}}})


def configure_software_tunnel(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """Configure GRE Tunnel"""
    for interface_directory in interface_data.values():
        # Configure tunnel interface
        path_oc_physical = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                            interface_directory["oc_interface_index"]]
        openconfig_interface_physical = return_nested_dict(openconfig_interfaces, path_oc_physical)
        path_nso_physical = ["tailf-ned-cisco-ios-xr:interface", interface_directory["nso_interface_type"],
                             interface_directory["nso_interface_index"]]
        nso_before_interface = return_nested_dict(config_before, path_nso_physical)
        nso_leftover_interface = return_nested_dict(config_leftover, path_nso_physical)

        xr_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_physical)

        openconfig_interface_physical["openconfig-if-tunnel:tunnel"] = {"openconfig-if-tunnel:config": {}}
        path_oc_tunnel = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                          interface_directory["oc_interface_index"], "openconfig-if-tunnel:tunnel"]
        openconfig_interface_tunnel = return_nested_dict(openconfig_interfaces, path_oc_tunnel)

        xr_configure_tunnel_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface_tunnel)

        # source IP
        if nso_before_interface.get("tunnel", {}).get("source"):
            openconfig_interface_tunnel["openconfig-if-tunnel:config"][
                "openconfig-if-tunnel:src"] = nso_before_interface.get("tunnel", {}).get("source")
            del nso_leftover_interface["tunnel"]["source"]
        # destination IP
        if nso_before_interface.get("tunnel", {}).get("destination"):
            openconfig_interface_tunnel["openconfig-if-tunnel:config"][
                "openconfig-if-tunnel:dst"] = nso_before_interface.get("tunnel", {}).get("destination")
            del nso_leftover_interface["tunnel"]["destination"]
        # keepalives
        if nso_before_interface.get("keepalive", {}).get("values", {}).get(
                "interval") and nso_before_interface.get("keepalive", {}).get("values", {}).get(
            "retry"):
            openconfig_interface_tunnel["openconfig-if-tunnel:config"]["openconfig-if-tunnel-ext:keepalives"] = {
                "openconfig-if-tunnel-ext:period": nso_before_interface.get("keepalive", {}).get(
                    "values", {}).get("interval"),
                "openconfig-if-tunnel-ext:retries": nso_before_interface.get("keepalive", {}).get(
                    "values", {}).get("retry")}
            del nso_leftover_interface["keepalive"]


def xr_interface_config(nso_before_interface: dict, nso_leftover_interface: dict, openconfig_interface: dict, sub_interface: bool=False) -> None:
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
    if not sub_interface and nso_before_interface.get("mtu"):
        openconfig_interface["openconfig-interfaces:config"]["openconfig-interfaces:mtu"] = nso_before_interface.get(
            "mtu")
        try:
            del nso_leftover_interface["mtu"]
        except:
            pass


def xr_interface_hold_time(config_before: dict, config_leftover: dict, v: dict) -> None:
    """Configure physical interface hold-time (carrier-delay)"""
    if config_before["tailf-ned-cisco-ios-xr:interface"][v["nso_interface_type"]][v["nso_interface_index"]].get(
            "carrier-delay", {}).get("msec"):
        openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"][
            v["oc_interface_index"]]["openconfig-interfaces:hold-time"] = {"openconfig-interfaces:config": {
            "openconfig-interfaces:down": config_before["tailf-ned-cisco-ios-xr:interface"][v["nso_interface_type"]][
                v["nso_interface_index"]].get("carrier-delay", {}).get("msec")}}
        del config_leftover["tailf-ned-cisco-ios-xr:interface"][v["nso_interface_type"]][v["nso_interface_index"]][
            "carrier-delay"]["msec"]


def xr_configure_vrrp(nso_before: dict, nso_leftover: dict, interfaces: dict):
    """Configure VRRP"""
    for vrrp_instance in nso_before.get("tailf-ned-cisco-ios-xr:router", {}).get("vrrp", {}).get("interface"):
        service_vrrp = {"openconfig-if-ip:vrrp": {"openconfig-if-ip:vrrp-group": []}}
        for vrrp_group in vrrp_instance.get("address-family", {}).get("ipv4", {}).get("vrrp", []):
            # Group
            service_vrrp_group = {"openconfig-if-ip:virtual-router-id": vrrp_group.get("id"),
                                  "openconfig-if-ip:config": {
                                      "openconfig-if-ip:virtual-router-id": vrrp_group.get("id")}}
            # Preempt delay
            if vrrp_group.get("preempt", {}).get("delay"):
                service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:preempt-delay"] = vrrp_group.get(
                    "preempt", {}).get("delay")
            # Preempt
            if vrrp_group.get("preempt"):
                service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:preempt"] = True
            # Priority
            if vrrp_group.get("priority"):
                service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:priority"] = vrrp_group.get("priority")
            # VRRP Address
            service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:virtual-address"] = []
            for ip in vrrp_group.get("address", []):
                service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:virtual-address"].append(ip["ip"])
            # Timers advertise
            if vrrp_group.get("timer", {}).get("time-value"):
                service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:advertisement-interval"] = int(
                    vrrp_group.get("timer", {}).get("time-value")) * 100
            service_vrrp["openconfig-if-ip:vrrp"]["openconfig-if-ip:vrrp-group"].append(service_vrrp_group)
        # TODO process IPV6
        # Apply to OC interfaces
        if_type, if_name = common.get_interface_type_number_and_subinterface(vrrp_instance["name"])

        if "." in if_name:
            if_type = f"{if_type}-subinterface"
        openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"][
            interfaces[if_type][if_name]["oc_interface_index"]]["openconfig-interfaces:subinterfaces"][
            "openconfig-interfaces:subinterface"][interfaces[if_type][if_name]["oc_sub_interface_place_counter"]][
            "openconfig-if-ip:ipv4"]["openconfig-if-ip:addresses"]["openconfig-if-ip:address"][0].update(service_vrrp)
    del nso_leftover["tailf-ned-cisco-ios-xr:router"]["vrrp"]


def xr_configure_hsrp(nso_before: dict, nso_leftover: dict, interfaces: dict):
    """Configure HSRP"""
    for hsrp_instance in nso_before.get("tailf-ned-cisco-ios-xr:router", {}).get("hsrp", {}).get("interface"):
        service_hsrp = {"openconfig-if-ip-mdd-ext:hsrp": {"openconfig-if-ip-mdd-ext:hsrp-group": []}}
        for hsrp_group in hsrp_instance.get("address-family", {}).get("ipv4", {}).get("hsrp-version1-list").get("hsrp",
                                                                                                                []):
            # Group
            service_hsrp_group = {"openconfig-if-ip-mdd-ext:group-number": hsrp_group.get("id"),
                                  "openconfig-if-ip-mdd-ext:config": {
                                      "openconfig-if-ip-mdd-ext:group-number": hsrp_group.get("id")}}
            # Preempt delay
            if hsrp_group.get("preempt", {}).get("delay"):
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"][
                    "openconfig-if-ip-mdd-ext:preempt-delay"] = hsrp_group.get(
                    "preempt", {}).get("delay")
            # Preempt
            if hsrp_group.get("preempt"):
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:preempt"] = True
            # Priority
            if hsrp_group.get("priority"):
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"][
                    "openconfig-if-ip-mdd-ext:priority"] = hsrp_group.get("priority")
            # HSRP Address
            service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:virtual-address"] = []
            if hsrp_group.get("address"):
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"][
                    "openconfig-if-ip-mdd-ext:virtual-address"].append(hsrp_group.get("address"))
            # Timers advertise
            if hsrp_group.get("timers", {}):
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:timers"] = {}
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:timers"][
                    "openconfig-if-ip-mdd-ext:hello-interval"] = hsrp_group.get("timers", {}).get("hello-seconds")
                service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:timers"][
                    "openconfig-if-ip-mdd-ext:holdtime"] = hsrp_group.get("timers", {}).get("hold-seconds")
            service_hsrp["openconfig-if-ip-mdd-ext:hsrp"]["openconfig-if-ip-mdd-ext:hsrp-group"].append(
                service_hsrp_group)
        # TODO process IPV6
        # Apply to OC interfaces
        if_type, if_name = common.get_interface_type_number_and_subinterface(hsrp_instance["name"])
        openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"][
            interfaces[if_type][if_name]["oc_interface_index"]]["openconfig-interfaces:subinterfaces"][
            "openconfig-interfaces:subinterface"][interfaces[if_type][if_name]["oc_sub_interface_place_counter"]][
            "openconfig-if-ip:ipv4"]["openconfig-if-ip:addresses"]["openconfig-if-ip:address"][0].update(service_hsrp)
    del nso_leftover["tailf-ned-cisco-ios-xr:router"]["hsrp"]


def xr_interfaces(config_before: dict, config_leftover: dict, interfaces: dict) -> None:
    """
    Translates NSO XR NED to MDD OpenConfig Interfaces Config
    """
    # Identify interface types
    for interface_type in interfaces:
        for interface in interfaces[interface_type]:
            # Assign default interface types
            interfaces[interface_type][interface]["oc_type"] = nso_to_oc_interface_types.get(interface_type,
                                                                                             "unsupported")
            openconfig_interfaces["openconfig-interfaces:interfaces"]["openconfig-interfaces:interface"][
                interfaces[interface_type][interface]["oc_interface_index"]]["openconfig-interfaces:config"][
                "openconfig-interfaces:type"] = nso_to_oc_interface_types[interface_type]

    for interface_type in interfaces:
        for v in interfaces[interface_type].values():
            if_types_with_subifs = ["ethernetCsmacd", "softwareLoopback", "ieee8023adLag"]
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

    # VRRP
    if config_before.get("tailf-ned-cisco-ios-xr:router", {}).get("vrrp"):
        xr_configure_vrrp(config_before, config_leftover, interfaces)
    # HSRP
    if config_before.get("tailf-ned-cisco-ios-xr:router", {}).get("hsrp"):
        xr_configure_hsrp(config_before, config_leftover, interfaces)


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
    :return: MDD Openconfig Interfaces configuration: dict
    """

    interfaces = create_interface_dict(before)
    xr_interfaces(before, leftover, interfaces)
    translation_notes += interfaces_notes

    return openconfig_interfaces


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
    config_name = "_interfaces"
    config_remaining_name = "_remaining_interfaces"
    oc_name = "_openconfig_interfaces"
    common.print_and_test_configs(
        "xr1", config_before_dict, config_leftover_dict, openconfig_interfaces,
        config_name, config_remaining_name, oc_name, interfaces_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xr import common_xr
        from package_nso_to_oc import common
    else:
        from xr import common_xr
        import common
