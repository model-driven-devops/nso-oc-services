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

port_speeds = {
    "10": "SPEED_10MB",
    "100": "SPEED_100MB",
    "1000": "SPEED_1GB",
    "2500": "SPEED_2500MB",
    "5000": "SPEED_5GB",
    "10000": "SPEED_10GB",
    "25000": "SPEED_25GB",
    "40000": "SPEED_40GB",
    "50000": "SPEED_50GB",
    "100000": "SPEED_100GB",
    "200000": "SPEED_200GB",
    "400000": "SPEED_400GB",
    "600000": "SPEED_600GB",
    "800000": "SPEED_800GB",
}

def interfaces_notes_add(note):
    interfaces_notes.append(note)


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
                    oc_interface_index += 1  # Do not increase oc_interface_index for sub-interfaces
                old_nso_index = nso_index
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
    return interface_dict


def configure_switched_vlan(nso_before_interface: dict, nso_leftover_interface: dict,
                            openconfig_interface: dict, interface_name: str) -> None:
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
    elif (type(nso_before_interface["switchport"].get("mode", {}).get("trunk", "")) is dict):
        openconfig_interface["openconfig-vlan:switched-vlan"][
            "openconfig-vlan:config"]["openconfig-vlan:interface-mode"] = "TRUNK"
        del nso_leftover_interface["switchport"]["mode"]
        if nso_before_interface["switchport"].get("trunk", {}).get("native", {}).get("vlan"):
            openconfig_interface["openconfig-vlan:switched-vlan"][
                "openconfig-vlan:config"]["openconfig-vlan:native-vlan"] = \
                nso_before_interface["switchport"]["trunk"].get("native", {}).get("vlan")
            del nso_leftover_interface["switchport"]["trunk"]["native"]
        if nso_before_interface["switchport"].get("trunk", {}).get("allowed", {}).get("vlan", {}).get("vlans"):
            openconfig_interface["openconfig-vlan:switched-vlan"][
                "openconfig-vlan:config"]["openconfig-vlan:trunk-vlans"] = \
                nso_before_interface["switchport"].get("trunk", {}).get("allowed", {}).get("vlan", {}).get("vlans")
            del nso_leftover_interface["switchport"]["trunk"]["allowed"]
    # Mode dynamic: desirable or dynamic: auto will be a converted to TRUNK in OC
    elif nso_before_interface["switchport"].get("mode", {}).get("dynamic"):
        openconfig_interface["openconfig-vlan:switched-vlan"][
            "openconfig-vlan:config"]["openconfig-vlan:interface-mode"] = "TRUNK"
        del nso_leftover_interface["switchport"]["mode"]
        if nso_before_interface["switchport"].get("trunk", {}).get("native", {}).get("vlan"):
            openconfig_interface["openconfig-vlan:switched-vlan"][
                "openconfig-vlan:config"]["openconfig-vlan:native-vlan"] = \
                nso_before_interface["switchport"]["trunk"].get("native", {}).get("vlan")
            del nso_leftover_interface["switchport"]["trunk"]["native"]
        if nso_before_interface["switchport"].get("trunk", {}).get("allowed", {}).get("vlan", {}).get("vlans"):
            openconfig_interface["openconfig-vlan:switched-vlan"][
                "openconfig-vlan:config"]["openconfig-vlan:trunk-vlans"] = \
                nso_before_interface["switchport"].get("trunk", {}).get("allowed", {}).get("vlan", {}).get("vlans")
            del nso_leftover_interface["switchport"]["trunk"]["allowed"]
        interfaces_notes_add(f"""
            Interface {interface_name} was set to trunking dynamic {nso_before_interface["switchport"].get("mode", {}).get("dynamic")}.
            OpenConfig configuration is now mode TRUNK. Review for issues.
        """)


def xe_configure_ipv4_interface(nso_before_interface: dict, nso_leftover_interface: dict,
                                openconfig_interface: dict) -> None:
    """IPv4 interface configurations"""
    oc_ipv4_structure = {"openconfig-if-ip:ipv4": {"openconfig-if-ip:addresses": {"openconfig-if-ip:address": []},
                                                   "openconfig-if-ip:config": {}}}
    if (nso_before_interface.get("ip") and not nso_before_interface.get("ip", {}).get("no-address")) or (
            nso_before_interface.get("vrrp")):
        openconfig_interface.update(oc_ipv4_structure)
        ip_and_masks = []

        if nso_before_interface["ip"].get("address", {}).get("primary"):
            ip_and_masks.append(nso_before_interface["ip"]["address"]["primary"])
        if len(nso_before_interface["ip"].get("address", {}).get("secondary", [])) > 0:
            ip_and_masks.extend(nso_before_interface["ip"]["address"]["secondary"])

        process_ip_address(ip_and_masks, openconfig_interface, nso_before_interface, nso_leftover_interface, "openconfig-if-ip")

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


def process_ip_address(ip_and_masks, openconfig_interface, nso_before_interface, nso_leftover_interface, key_prefix):
    vrrp_leftovers = []
    hsrp_leftovers = []

    for index, ip_and_mask in enumerate(ip_and_masks):
        ipv4_address_structure = {}

        if (ip_and_mask.get("address") and ip_and_mask.get("mask")):
            prefix = ipaddress.IPv4Network(
                f'{ip_and_mask.get("address")}/{ip_and_mask.get("mask")}',
                strict=False)
            mask = prefix.prefixlen
            ip = ip_and_mask.get("address")
            ipv4_address_structure.update({f"{key_prefix}:ip": ip,
                                           f"{key_prefix}:config": {f"{key_prefix}:ip": ip,
                                                                       f"{key_prefix}:prefix-length": mask}})
        if len(ipv4_address_structure) > 0:
            openconfig_interface[f"{key_prefix}:ipv4"][f"{key_prefix}:addresses"][
                f"{key_prefix}:address"].append(ipv4_address_structure)

        process_vrrp_hsrp(vrrp_leftovers, hsrp_leftovers, index, nso_before_interface, nso_leftover_interface, ipv4_address_structure)

    if len(vrrp_leftovers) > 0:
        nso_leftover_interface["vrrp"] = vrrp_leftovers
    elif "vrrp" in nso_leftover_interface and len(vrrp_leftovers) == 0:
        del nso_leftover_interface["vrrp"]
    if len(hsrp_leftovers) > 0:
        nso_leftover_interface["standby"]["standby-list"] = hsrp_leftovers
    elif "standby" in nso_leftover_interface and len(hsrp_leftovers) == 0:
        del nso_leftover_interface["standby"]

    ip_address = nso_leftover_interface.get("ip", {}).get("address", {})

    if ip_address.get("primary"):
        del nso_leftover_interface["ip"]["address"]["primary"]
    if ip_address.get("secondary"):
        del nso_leftover_interface["ip"]["address"]["secondary"]
    if type(nso_before_interface["ip"].get("address", {}).get("dhcp", "")) is dict:
        openconfig_interface[f"{key_prefix}:ipv4"][f"{key_prefix}:config"][
            f"{key_prefix}:dhcp-client"] = True
        del \
            nso_before_interface["ip"]["address"]
    else:
        openconfig_interface[f"{key_prefix}:ipv4"][f"{key_prefix}:config"][
            f"{key_prefix}:dhcp-client"] = False


def process_vrrp_hsrp(vrrp_leftovers, hsrp_leftovers, index, nso_before_interface, nso_leftover_interface, ipv4_address_structure):
    vrrp_before = nso_before_interface.get("vrrp")
    hsrp_before = nso_before_interface.get("standby", {}).get("standby-list")

    # VRRP
    if vrrp_before and len(vrrp_before) > index:
        (vrrp_dict, vrrp_leftover) = xe_configure_vrrp_interfaces(nso_before_interface, nso_leftover_interface, index)
        ipv4_address_structure.update(vrrp_dict)

        if vrrp_leftover:
            vrrp_leftovers.append(vrrp_leftover)
    # HSRP
    if hsrp_before and len(hsrp_before) > index:
        (hsrp_dict, hsrp_leftover) = xe_configure_hsrp_interfaces(nso_before_interface, nso_leftover_interface, index)
        ipv4_address_structure.update(hsrp_dict)

        if hsrp_leftover:
            hsrp_leftovers.append(hsrp_leftover)


def xe_configure_tunnel_ipv4_interface(nso_before_interface: dict, nso_leftover_interface: dict,
                                       openconfig_interface: dict) -> None:
    """Tunnel IPv4 interface configurations"""
    oc_ipv4_structure = {
        "openconfig-if-tunnel:ipv4": {"openconfig-if-tunnel:addresses": {"openconfig-if-tunnel:address": []},
                                      "openconfig-if-tunnel:config": {}}}
    if (nso_before_interface.get("ip") and not nso_before_interface.get("ip", {}).get("no-address")) or (
            nso_before_interface.get("vrrp")):
        openconfig_interface.update(oc_ipv4_structure)
        ip_and_masks = []

        if nso_before_interface["ip"].get("address", {}).get("primary"):
            ip_and_masks.append(nso_before_interface["ip"]["address"]["primary"])
        if len(nso_before_interface["ip"].get("address", {}).get("secondary", [])) > 0:
            ip_and_masks.extend(nso_before_interface["ip"]["address"]["secondary"])

        process_ip_address(ip_and_masks, openconfig_interface, nso_before_interface, nso_leftover_interface, "openconfig-if-tunnel")

        # IP MTU
        if nso_before_interface.get("ip", {}).get("mtu"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-tunnel:mtu"] = nso_before_interface.get("ip", {}).get("mtu")

            del nso_leftover_interface["ip"]["mtu"]
        # adjust TCP MSS
        if nso_before_interface.get("ip", {}).get("tcp", {}).get("adjust-mss"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:tcp-adjust-mss"] = nso_before_interface["ip"]["tcp"]["adjust-mss"]

            del nso_leftover_interface["ip"]["tcp"]["adjust-mss"]
        # IP redirects
        if nso_before_interface.get("ip", {}).get("redirects"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:redirects"] = True
            del nso_leftover_interface["ip"]["redirects"]
        elif nso_before_interface.get("ip", {}).get("redirects") is False:
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:redirects"] = False
            del nso_leftover_interface["ip"]["redirects"]
        # IP unreachables
        if nso_before_interface.get("ip", {}).get("unreachables"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:unreachables"] = True
            del nso_leftover_interface["ip"]["unreachables"]
        elif nso_before_interface.get("ip", {}).get(
                "unreachables") is False:
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:unreachables"] = False
            del nso_leftover_interface["ip"]["unreachables"]
        # Proxy-ARP
        if nso_before_interface.get("ip", {}).get("proxy-arp"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:proxy-arp"] = {
                "openconfig-if-tunnel:config": {"openconfig-if-tunnel:mode": "REMOTE_ONLY"}}
            del nso_leftover_interface["ip"]["proxy-arp"]
        elif nso_before_interface.get("ip", {}).get("proxy-arp") is False:
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:proxy-arp"] = {
                "openconfig-if-tunnel:config": {"openconfig-if-tunnel:mode": "DISABLE"}}
            del nso_leftover_interface["ip"]["proxy-arp"]
        # reply-mask
        if nso_before_interface.get("ip", {}).get("mask-reply"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:mask-reply"] = True
            del nso_leftover_interface["ip"]["mask-reply"]
        # NAT interface
        if nso_before_interface.get("ip", {}).get("nat", {}).get("inside"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:nat"] = {
                "openconfig-if-ip-mdd-ext:nat-choice": "inside"}
            del nso_leftover_interface["ip"]["nat"]["inside"]
        elif nso_before_interface.get("ip", {}).get("nat", {}).get("outside"):
            openconfig_interface["openconfig-if-tunnel:ipv4"]["openconfig-if-tunnel:config"][
                "openconfig-if-ip-mdd-ext:nat"] = {
                "openconfig-if-ip-mdd-ext:nat-choice": "outside"}
            del nso_leftover_interface["ip"]["nat"]["outside"]


def configure_software_loopback(config_before: dict, config_leftover: dict, interface_data: dict) -> None:
    """Configure Loopbacks"""
    for interface_directory in interface_data.values():
        path_oc_sub_if = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                          interface_directory["oc_interface_index"], "openconfig-interfaces:subinterfaces",
                          "openconfig-interfaces:subinterface", interface_directory["oc_sub_interface_place_counter"]]
        path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                   interface_directory["oc_interface_index"]]
        path_nso = ["tailf-ned-cisco-ios:interface", interface_directory["nso_interface_type"],
                    interface_directory["nso_interface_index"]]
        openconfig_interface_sub_if = return_nested_dict(openconfig_interfaces, path_oc_sub_if)
        openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)
        nso_before_interface = return_nested_dict(config_before, path_nso)
        nso_leftover_interface = return_nested_dict(config_leftover, path_nso)

        # Main Interface
        xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface)
        # Sub Interface
        xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_sub_if)
        xe_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface_sub_if)


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
            interface_name = interface_directory["nso_interface_type"] + str(
                config_before["tailf-ned-cisco-ios:interface"][interface_directory["nso_interface_type"]][
                    interface_directory["nso_interface_index"]]["name"])
            path_nso_physical = ["tailf-ned-cisco-ios:interface", interface_directory["nso_interface_type"],
                                 interface_directory["nso_interface_index"]]
            nso_before_interface = return_nested_dict(config_before, path_nso_physical)
            nso_leftover_interface = return_nested_dict(config_leftover, path_nso_physical)
            xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_physical)
            mtu_set(nso_before_interface, nso_leftover_interface, openconfig_interface_physical)
            openconfig_interface_physical.update({"openconfig-if-aggregate:aggregation": {
                "openconfig-if-aggregate:config": {"openconfig-if-aggregate:lag-type": "LACP"}}})
            path_oc_agg = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                           interface_directory["oc_interface_index"], "openconfig-if-aggregate:aggregation"]
            openconfig_interface_agg = return_nested_dict(openconfig_interfaces, path_oc_agg)
            if nso_before_interface.get("switchport"):
                configure_switched_vlan(nso_before_interface, nso_leftover_interface, openconfig_interface_agg,
                                        interface_name)
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
                             "openconfig-interfaces:subinterface",
                             interface_directory["oc_sub_interface_place_counter"]]

            openconfig_interface_subif = return_nested_dict(openconfig_interfaces, path_oc_subif)

            xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface_subif)
            xe_configure_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface_subif)


def check_for_ip_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def configure_software_tunnel(config_before: dict, config_leftover: dict, interface_data: dict, if_ip: dict) -> None:
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
        path_oc_tunnel = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                          interface_directory["oc_interface_index"], "openconfig-if-tunnel:tunnel"]
        openconfig_interface_tunnel = return_nested_dict(openconfig_interfaces, path_oc_tunnel)

        xe_configure_tunnel_ipv4_interface(nso_before_interface, nso_leftover_interface, openconfig_interface_tunnel)

        # source IP
        if nso_before_interface.get("tunnel", {}).get("source"):
            tunnel_src = nso_before_interface.get("tunnel", {}).get("source")
            if check_for_ip_address(tunnel_src):
                openconfig_interface_tunnel["openconfig-if-tunnel:config"][
                    "openconfig-if-tunnel:src"] = tunnel_src
            else:
                openconfig_interface_tunnel["openconfig-if-tunnel:config"][
                "openconfig-if-tunnel:src"] = if_ip.get(tunnel_src)
            del nso_leftover_interface["tunnel"]["source"]
        # destination IP
        if nso_before_interface.get("tunnel", {}).get("destination"):
            openconfig_interface_tunnel["openconfig-if-tunnel:config"][
                "openconfig-if-tunnel:dst"] = nso_before_interface.get("tunnel", {}).get("destination")
            del nso_leftover_interface["tunnel"]["destination"]
        # key
        if nso_before_interface.get("tunnel", {}).get("key"):
            openconfig_interface_tunnel["openconfig-if-tunnel:config"][
                "openconfig-if-tunnel:gre-key"] = nso_before_interface.get("tunnel", {}).get("key")
            del nso_leftover_interface["tunnel"]["key"]
        # PMTUD
        if type(nso_before_interface.get("tunnel", {}).get("path-mtu-discovery", "")) is dict:
            openconfig_interface_tunnel["openconfig-if-tunnel:config"][
                "openconfig-if-tunnel-ext:tunnel-path-mtu-discovery"] = True
            del nso_leftover_interface["tunnel"]["path-mtu-discovery"]
        # keepalives
        if nso_before_interface.get("keepalive-period-retries", {}).get("keepalive", {}).get(
                "period") and nso_before_interface.get("keepalive-period-retries", {}).get("keepalive", {}).get(
            "retries"):
            openconfig_interface_tunnel["openconfig-if-tunnel:config"]["openconfig-if-tunnel-ext:keepalives"] = {
                "openconfig-if-tunnel-ext:period": nso_before_interface.get("keepalive-period-retries", {}).get(
                    "keepalive", {}).get("period"),
                "openconfig-if-tunnel-ext:retries": nso_before_interface.get("keepalive-period-retries", {}).get(
                    "keepalive", {}).get("retries")}
            del nso_leftover_interface["keepalive-period-retries"]


def mtu_set(nso_before_interface: dict, nso_leftover_interface: dict, openconfig_interface: dict) -> None:
    """
    Only on physical interfaces.
    Configures interface MTU.
    """
    # MTU
    if nso_before_interface.get("mtu"):
        openconfig_interface["openconfig-interfaces:config"]["openconfig-interfaces:mtu"] = nso_before_interface.get(
            "mtu")
        try:
            del nso_leftover_interface["mtu"]
        except:
            pass


def xe_interface_encapsulation(nso_before_interface: dict, nso_leftover_interface: dict, openconfig_interface: dict) -> None:
    # Encapsulation
    if nso_before_interface.get("encapsulation", {}).get("dot1Q", {}).get("vlan-id"):
        openconfig_interface.update(
            {"openconfig-vlan:vlan": {"openconfig-vlan:config": {
                "openconfig-vlan:vlan-id": nso_before_interface.get("encapsulation", {}).get("dot1Q", {}).get(
                    "vlan-id")}}})
        del nso_leftover_interface["encapsulation"]


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


def xe_interface_storm_control(openconfig_interface: dict, nso_before_interface: dict, config_leftover: dict, v: dict) -> None:
    """Configure physical interface storm control"""

    openconfig_interface.update({"openconfig-if-ethernet:ethernet": {
        "openconfig-if-ethernet:config": {},
        "openconfig-if-ethernet-mdd-ext:storm-control": {
            "openconfig-if-ethernet-mdd-ext:broadcast": {
                "openconfig-if-ethernet-mdd-ext:level": {
                    "openconfig-if-ethernet-mdd-ext:config": {}
                }
            },
            "openconfig-if-ethernet-mdd-ext:unicast": {
                "openconfig-if-ethernet-mdd-ext:level": {
                    "openconfig-if-ethernet-mdd-ext:config": {}
                }
            }
        }
    }})
    # broadcast
    if nso_before_interface.get("storm-control", {}).get("broadcast", {}).get("level-bps-pps", {}).get("level", {}).get("bps"):
        openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet-mdd-ext:storm-control"][
            "openconfig-if-ethernet-mdd-ext:broadcast"]["openconfig-if-ethernet-mdd-ext:level"][
            "openconfig-if-ethernet-mdd-ext:config"]["openconfig-if-ethernet-mdd-ext:suppression-type"] = 'BPS'
        openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet-mdd-ext:storm-control"][
            "openconfig-if-ethernet-mdd-ext:broadcast"]["openconfig-if-ethernet-mdd-ext:level"][
            "openconfig-if-ethernet-mdd-ext:config"]["openconfig-if-ethernet-mdd-ext:bps"] = nso_before_interface.get("storm-control", {}).get("broadcast", {}).get("level-bps-pps", {}).get("level", {}).get("bps")
        del config_leftover["tailf-ned-cisco-ios:interface"][v["nso_interface_type"]][v["nso_interface_index"]][
                "storm-control"]["broadcast"]["level-bps-pps"]["level"]["bps"]
    elif nso_before_interface.get("storm-control", {}).get("broadcast", {}).get("level-bps-pps", {}).get("level", {}).get("pps"):
        openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet-mdd-ext:storm-control"][
            "openconfig-if-ethernet-mdd-ext:broadcast"]["openconfig-if-ethernet-mdd-ext:level"][
            "openconfig-if-ethernet-mdd-ext:config"]["openconfig-if-ethernet-mdd-ext:suppression-type"] = 'PPS'
        openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet-mdd-ext:storm-control"][
            "openconfig-if-ethernet-mdd-ext:broadcast"]["openconfig-if-ethernet-mdd-ext:level"][
            "openconfig-if-ethernet-mdd-ext:config"]["openconfig-if-ethernet-mdd-ext:pps"] = nso_before_interface.get("storm-control", {}).get("broadcast", {}).get("level-bps-pps", {}).get("level", {}).get("pps")
        del config_leftover["tailf-ned-cisco-ios:interface"][v["nso_interface_type"]][v["nso_interface_index"]][
                "storm-control"]["broadcast"]["level-bps-pps"]["level"]["pps"]
    # unicast
    if nso_before_interface.get("storm-control", {}).get("unicast", {}).get("level-bps-pps", {}).get("level", {}).get("bps"):
        openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet-mdd-ext:storm-control"][
            "openconfig-if-ethernet-mdd-ext:unicast"]["openconfig-if-ethernet-mdd-ext:level"][
            "openconfig-if-ethernet-mdd-ext:config"]["openconfig-if-ethernet-mdd-ext:suppression-type"] = 'BPS'
        openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet-mdd-ext:storm-control"][
            "openconfig-if-ethernet-mdd-ext:unicast"]["openconfig-if-ethernet-mdd-ext:level"][
            "openconfig-if-ethernet-mdd-ext:config"]["openconfig-if-ethernet-mdd-ext:bps"] = nso_before_interface.get("storm-control", {}).get("unicast", {}).get("level-bps-pps", {}).get("level", {}).get("bps")
        del config_leftover["tailf-ned-cisco-ios:interface"][v["nso_interface_type"]][v["nso_interface_index"]][
                "storm-control"]["unicast"]["level-bps-pps"]["level"]["bps"]
    elif nso_before_interface.get("storm-control", {}).get("unicast", {}).get("level-bps-pps", {}).get("level", {}).get("pps"):
        openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet-mdd-ext:storm-control"][
            "openconfig-if-ethernet-mdd-ext:unicast"]["openconfig-if-ethernet-mdd-ext:level"][
            "openconfig-if-ethernet-mdd-ext:config"]["openconfig-if-ethernet-mdd-ext:suppression-type"] = 'PPS'
        openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet-mdd-ext:storm-control"][
            "openconfig-if-ethernet-mdd-ext:unicast"]["openconfig-if-ethernet-mdd-ext:level"][
            "openconfig-if-ethernet-mdd-ext:config"]["openconfig-if-ethernet-mdd-ext:pps"] = nso_before_interface.get("storm-control", {}).get("unicast", {}).get("level-bps-pps", {}).get("level", {}).get("pps")
        del config_leftover["tailf-ned-cisco-ios:interface"][v["nso_interface_type"]][v["nso_interface_index"]][
                "storm-control"]["unicast"]["level-bps-pps"]["level"]["pps"]


def xe_configure_vrrp_interfaces(nso_before_interface: dict, nso_leftover_interface: dict, index: int) -> tuple:
    """Configure VRRP"""
    service_vrrp = {"openconfig-if-ip:vrrp": {"openconfig-if-ip:vrrp-group": []}}
    vrrp_leftover = None
    group = nso_before_interface["vrrp"][index]
    current_vrrp = nso_leftover_interface["vrrp"][index]

    if group.get("id"):
        # Group
        service_vrrp_group = {"openconfig-if-ip:virtual-router-id": group.get("id"),
                                "openconfig-if-ip:config": {"openconfig-if-ip:virtual-router-id": group.get("id")}}
        del current_vrrp["id"]
        # Preempt delay
        if group.get("preempt", {}).get("delay", {}).get("minimum"):
            service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:preempt-delay"] = group.get("preempt",
                                                                                                        {}).get(
                "delay", {}).get("minimum")
            del current_vrrp["preempt"]["delay"]
        # Preempt
        if group.get("preempt"):
            service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:preempt"] = True
            del current_vrrp["preempt"]
        # Priority
        if group.get("priority"):
            service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:priority"] = group.get("priority")
            del current_vrrp["priority"]
        # VRRP Address
        if group.get("ip", {}).get("address"):
            service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:virtual-address"] = []
            service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:virtual-address"].append(
                group.get("ip", {}).get("address"))
        for secondary_address in group.get("ip", {}).get("secondary-address", []):
            service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:virtual-address"].append(
                secondary_address["address"])
        if current_vrrp.get("ip"):
            del current_vrrp["ip"]
        # Timers advertise
        if group.get("timers", {}).get("advertise", {}).get("seconds"):
            service_vrrp_group["openconfig-if-ip:config"]["openconfig-if-ip:advertisement-interval"] = int(
                group.get("timers", {}).get("advertise").get("seconds")) * 100
            del current_vrrp["timers"]["advertise"]

            if len(current_vrrp["timers"]) == 0:
                del current_vrrp["timers"]
        service_vrrp["openconfig-if-ip:vrrp"]["openconfig-if-ip:vrrp-group"].append(service_vrrp_group)
        # Keep object if it contains more properties
        if current_vrrp and len(current_vrrp) > 0:
            vrrp_leftover = current_vrrp

    return (service_vrrp, vrrp_leftover)


def xe_configure_hsrp_interfaces(nso_before_interface: dict, nso_leftover_interface: dict, index: int) -> tuple:
    """Configure HSRP"""
    service_hsrp = {"openconfig-if-ip-mdd-ext:hsrp": {"openconfig-if-ip-mdd-ext:hsrp-group": []}}
    hsrp_leftover = None
    group = nso_before_interface["standby"]["standby-list"][index]
    current_standby = nso_leftover_interface["standby"]["standby-list"][index]

    if group.get("group-number"):
        # Group
        service_hsrp_group = {"openconfig-if-ip-mdd-ext:group-number": group.get("group-number"),
                                "openconfig-if-ip-mdd-ext:config": {
                                    "openconfig-if-ip-mdd-ext:group-number": group.get("group-number")}}
        del current_standby["group-number"]
        # Preempt delay
        if group.get("preempt", {}).get("delay", {}).get("minimum"):
            service_hsrp_group["openconfig-if-ip-mdd-ext:config"][
                "openconfig-if-ip-mdd-ext:preempt-delay"] = group.get("preempt",
                                                                        {}).get(
                "delay", {}).get("minimum")
            del current_standby["preempt"]["delay"]
        # Preempt
        if group.get("preempt"):
            service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:preempt"] = True
            del current_standby["preempt"]
        # Priority
        if group.get("priority"):
            service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:priority"] = group.get(
                "priority")
            del current_standby["priority"]
        # VRRP Address
        if group.get("ip", {}).get("address"):
            service_hsrp_group["openconfig-if-ip-mdd-ext:config"]["openconfig-if-ip-mdd-ext:virtual-address"] = []
            service_hsrp_group["openconfig-if-ip-mdd-ext:config"][
                "openconfig-if-ip-mdd-ext:virtual-address"].append(
                group.get("ip", {}).get("address"))
        for secondary_address in group.get("ip", {}).get("secondary", []):
            service_hsrp_group["openconfig-if-ip-mdd-ext:config"][
                "openconfig-if-ip-mdd-ext:virtual-address"].append(secondary_address["address"])
        if current_standby.get("ip"):
            del current_standby["ip"]
        # Timers
        if group.get("timers", {}).get("hello-interval", {}).get("seconds") and group.get("timers", {}).get(
                "hold-time", {}).get("seconds"):
            service_hsrp_group["openconfig-if-ip-mdd-ext:config"].update({"openconfig-if-ip-mdd-ext:timers": {
                "openconfig-if-ip-mdd-ext:hello-interval": int(
                    group.get("timers", {}).get("hello-interval").get("seconds")),
                "openconfig-if-ip-mdd-ext:holdtime": int(group.get("timers", {}).get("hold-time").get("seconds"))
            }})
            del current_standby["timers"]["hello-interval"]
            del current_standby["timers"]["hold-time"]

            if len(current_standby["timers"]) == 0:
                del current_standby["timers"]

        service_hsrp["openconfig-if-ip-mdd-ext:hsrp"]["openconfig-if-ip-mdd-ext:hsrp-group"].append(
            service_hsrp_group)

        # Keep object if it contains more properties
        if current_standby and len(current_standby) > 0:
            hsrp_leftover = current_standby

    return (service_hsrp, hsrp_leftover)


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
        interface_name = interface_directory["nso_interface_type"] + str(
            config_before["tailf-ned-cisco-ios:interface"][interface_directory["nso_interface_type"]][
                interface_directory["nso_interface_index"]]["name"])
        path_nso = ["tailf-ned-cisco-ios:interface", interface_directory["nso_interface_type"],
                    interface_directory["nso_interface_index"]]
        nso_before_interface = return_nested_dict(config_before, path_nso)
        nso_leftover_interface = return_nested_dict(config_leftover, path_nso)

        # Configure sub-interface
        xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface)
        xe_interface_encapsulation(nso_before_interface, nso_leftover_interface, openconfig_interface)

        path_oc = ["openconfig-interfaces:interfaces", "openconfig-interfaces:interface",
                   interface_directory["oc_interface_index"]]
        openconfig_interface = return_nested_dict(openconfig_interfaces, path_oc)

        # Configure physical interface
        xe_interface_config(nso_before_interface, nso_leftover_interface, openconfig_interface)
        mtu_set(nso_before_interface, nso_leftover_interface, openconfig_interface)
        # Configure physical interface hold-time (carrier-delay)
        xe_interface_hold_time(config_before, config_leftover, interface_directory)

        # Configure ethernet settings
        if nso_before_interface.get("storm-control"):
            xe_interface_storm_control(openconfig_interface, nso_before_interface, config_leftover, interface_directory)
        else:
            openconfig_interface.update({"openconfig-if-ethernet:ethernet": {"openconfig-if-ethernet:config": {}}})
        if nso_before_interface.get("negotiation", {}).get("auto"):
            openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                "openconfig-if-ethernet:auto-negotiate"] = True
            del nso_leftover_interface["negotiation"]["auto"]
        elif (nso_before_interface.get("speed") == "auto") and (nso_before_interface.get("duplex") == "auto"):
            openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
            "openconfig-if-ethernet:auto-negotiate"] = True
            del nso_leftover_interface["speed"]
            del nso_leftover_interface["duplex"]
        else:
            if nso_before_interface.get("speed", "").isdigit():
                if port_speeds.get(nso_before_interface.get("speed")):
                    openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                        "openconfig-if-ethernet:port-speed"] = port_speeds.get(nso_before_interface.get("speed"))
                    del nso_leftover_interface["speed"]
            if nso_before_interface.get("duplex") == "full" or nso_before_interface.get("duplex") == "half":
                openconfig_interface["openconfig-if-ethernet:ethernet"]["openconfig-if-ethernet:config"][
                    "openconfig-if-ethernet:duplex-mode"] = nso_before_interface.get("duplex").upper()
                del nso_leftover_interface["duplex"]
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
            configure_switched_vlan(nso_before_interface, nso_leftover_interface, openconfig_interface, interface_name)
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


def xe_interfaces(config_before: dict, config_leftover: dict, interfaces: dict, if_ip: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig Interfaces Config
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
            configure_software_tunnel(config_before, config_leftover, interfaces[interface_type], if_ip)
        if nso_to_oc_interface_types[interface_type] == "vasi":
            configure_software_vasi(config_before, config_leftover, interfaces[interface_type])


def main(before: dict, leftover: dict, if_ip: dict, translation_notes: list = []) -> dict:
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
    :param if_ip: Map of interface names to IP addresses: dict
    :return: MDD Openconfig Interfaces configuration: dict
    """

    interfaces = create_interface_dict(before)
    xe_interfaces(before, leftover, interfaces, if_ip)
    translation_notes += interfaces_notes

    return openconfig_interfaces


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
    main(config_before_dict, config_leftover_dict, interface_ip_dict)
    config_name = "_interfaces"
    config_remaining_name = "_remaining_interfaces"
    oc_name = "_openconfig_interfaces"
    common.print_and_test_configs(
        "xe1", config_before_dict, config_leftover_dict, openconfig_interfaces,
        config_name, config_remaining_name, oc_name, interfaces_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc import common
    else:
        from xe import common_xe
        import common
