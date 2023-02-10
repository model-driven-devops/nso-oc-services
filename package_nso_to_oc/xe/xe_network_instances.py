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
                "openconfig-network-instance:interfaces": {"openconfig-network-instance:interface": []},
                "openconfig-network-instance:vlans": {}
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
                process_rd_rt(temp_vrf, vrf, vrf_index, config_leftover)

                del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["address-family"]
            openconfig_network_instances["openconfig-network-instance:network-instances"][
                "openconfig-network-instance:network-instance"].append(temp_vrf)

    interfaces_by_vrf = get_interfaces_by_vrf(config_before)
    route_forwarding_list_by_vrf = get_route_forwarding_list_by_vrf(config_before)
    configure_network_instances(config_before, config_leftover, interfaces_by_vrf, route_forwarding_list_by_vrf)

    cleanup_null_ospf_leftovers(config_leftover)
    cleanup_null_static_route_leftovers(config_leftover)

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

def get_route_forwarding_list_by_vrf(config_before):
    route_forwarding_list_by_vrf = {}
    ip_obj = config_before.get("tailf-ned-cisco-ios:ip", {"route": {}}).get("route", {})

    route_forwarding_list_by_vrf["default"] = {
        common_xe.IP_FORWARDING_LIST: copy.deepcopy(ip_obj.get(common_xe.IP_FORWARDING_LIST, [])),
        common_xe.INTF_LIST: copy.deepcopy(ip_obj.get(common_xe.INTF_LIST, [])),
        common_xe.IP_INTF_FORWARDING_LIST: copy.deepcopy(ip_obj.get(common_xe.IP_INTF_FORWARDING_LIST, []))
    }

    for index, vrf in enumerate(ip_obj.get("vrf", [])):
        route_forwarding_list_by_vrf[vrf["name"]] = {
            "vrf-index": index,
            common_xe.IP_FORWARDING_LIST: copy.deepcopy(vrf.get(common_xe.IP_FORWARDING_LIST, [])),
            common_xe.INTF_LIST: copy.deepcopy(vrf.get(common_xe.INTF_LIST, [])),
            common_xe.IP_INTF_FORWARDING_LIST: copy.deepcopy(vrf.get(common_xe.IP_INTF_FORWARDING_LIST, []))
        }

    return route_forwarding_list_by_vrf

def configure_network_instances(config_before, config_leftover, interfaces_by_vrf, route_forwarding_list_by_vrf):
    for net_inst in openconfig_network_instances["openconfig-network-instance:network-instances"][
        "openconfig-network-instance:network-instance"]:
        configure_network_interfaces(net_inst, interfaces_by_vrf)

        if len(interfaces_by_vrf.get(net_inst["openconfig-network-instance:name"], [])) > 0:
            vrf_interfaces = interfaces_by_vrf.get(net_inst["openconfig-network-instance:name"])
            xe_ospfv2.configure_xe_ospf(net_inst, vrf_interfaces, config_before, config_leftover)
        if len(route_forwarding_list_by_vrf.get(net_inst["openconfig-network-instance:name"], [])) > 0:
            vrf_forwarding_list = route_forwarding_list_by_vrf.get(net_inst["openconfig-network-instance:name"])
            xe_static_route.configure_xe_static_routes(net_inst, vrf_forwarding_list, config_leftover, network_instances_notes)

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

        if (interface["type"] != "Tunnel") and (interface["type"] != "Vlan") and (interface["type"] != "Port-channel"):
            subinterface = '0' if len(name_split) == 1 else name_split[1]
            new_interface["openconfig-network-instance:config"][
                "openconfig-network-instance:subinterface"] = subinterface
        elif interface["type"] == "Port-channel":  # Port-channel's don't have a sub-if 0
            if len(name_split) > 1:
                new_interface["openconfig-network-instance:config"]["openconfig-network-instance:subinterface"] = \
                name_split[1]

        net_inst["openconfig-network-instance:interfaces"]["openconfig-network-instance:interface"].append(new_interface)

def process_rd_rt(temp_vrf, vrf, vrf_index, config_leftover):
    if "rd" in vrf:
        temp_vrf["openconfig-network-instance:config"][
            "openconfig-network-instance:route-distinguisher"] = vrf["rd"]
        temp_vrf["openconfig-network-instance:config"][
            "openconfig-network-instance-ext:route-targets-import"] = []
        temp_vrf["openconfig-network-instance:config"][
            "openconfig-network-instance-ext:route-targets-export"] = []

        # RD is required to create RTs
        if "route-target" in vrf:
            process_rt(temp_vrf, vrf, "import")
            process_rt(temp_vrf, vrf, "export")
            del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["route-target"]

        del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["rd"]

def process_rt(temp_vrf, vrf, rt_type):
    for rt in vrf["route-target"].get(rt_type, []):
        if "asn-ip" in rt:
            temp_vrf["openconfig-network-instance:config"][
                f"openconfig-network-instance-ext:route-targets-{rt_type}"].append(rt["asn-ip"])

def cleanup_null_ospf_leftovers(config_leftover):
    ospf_leftover = config_leftover.get("tailf-ned-cisco-ios:router", {}).get("ospf", [])
    updated_ospf_list = []

    for ospf_index in range(len(ospf_leftover)):
        cleanup_neighbors(ospf_leftover[ospf_index])
        cleanup_traffic_area(ospf_leftover[ospf_index])
        cleanup_virtual_link(ospf_leftover[ospf_index])

        if len(ospf_leftover[ospf_index]) > 0:
            updated_ospf_list.append(ospf_leftover[ospf_index])
    
    if len(updated_ospf_list) > 0:
        config_leftover.get("tailf-ned-cisco-ios:router", {})["ospf"] = updated_ospf_list
    elif "ospf" in config_leftover.get("tailf-ned-cisco-ios:router", {}):
        del config_leftover["tailf-ned-cisco-ios:router"]["ospf"]

def cleanup_neighbors(ospf_leftover):
    if "neighbor" in ospf_leftover:
        del ospf_leftover["neighbor"]

def cleanup_virtual_link(ospf_leftover):
    if len(ospf_leftover.get("area", [])) < 1:
        return

    for area in ospf_leftover["area"]:
        updated_virtual_link_list = []

        for virtual_link in area.get("virtual-link", []):
            if virtual_link:
                updated_virtual_link_list.append(virtual_link)

        if len(updated_virtual_link_list) > 0:
            area["virtual-link"] = updated_virtual_link_list
        elif "virtual-link" in area:
            del area["virtual-link"]

def cleanup_traffic_area(ospf_leftover):
    if not "mpls" in ospf_leftover:
        return

    updated_traffic_area_list = []

    for area_item in ospf_leftover["mpls"].get("traffic-eng", {}).get("area", []):
        if area_item:
            updated_traffic_area_list.append(area_item)
        
    if len(updated_traffic_area_list) > 0:
        ospf_leftover["mpls"]["traffic-eng"]["area"] = updated_traffic_area_list
    elif "area" in ospf_leftover["mpls"].get("traffic-eng", {}):
        del ospf_leftover["mpls"]["traffic-eng"]["area"]

def cleanup_null_static_route_leftovers(config_leftover):
    if "route" in config_leftover.get("tailf-ned-cisco-ios:ip", {}):
        cleanup_static_routes(config_leftover["tailf-ned-cisco-ios:ip"]["route"])
    
    cleanup_vrf_null_leftover_static_routes(config_leftover)

    if "route" in config_leftover.get("tailf-ned-cisco-ios:ip", {}) and len(config_leftover["tailf-ned-cisco-ios:ip"]["route"]) == 0:
        del config_leftover["tailf-ned-cisco-ios:ip"]["route"]

def cleanup_vrf_null_leftover_static_routes(config_leftover):
    if len(config_leftover.get("tailf-ned-cisco-ios:ip", {"route": {}}).get("route", {}).get("vrf", [])) > 0:
        updated_vrf_list = []

        for vrf in config_leftover["tailf-ned-cisco-ios:ip"]["route"]["vrf"]:
            cleanup_static_routes(vrf)

            if len(vrf) > 0:
                updated_vrf_list.append(vrf)
        
        if len(updated_vrf_list) > 0:
            config_leftover["tailf-ned-cisco-ios:ip"]["route"]["vrf"] = updated_vrf_list
        else:
            del config_leftover["tailf-ned-cisco-ios:ip"]["route"]["vrf"]

def cleanup_static_routes(leftover_route):
    if common_xe.IP_FORWARDING_LIST in leftover_route:
        updated_ip_forwarding_list_leftover = get_updated_configs(leftover_route[common_xe.IP_FORWARDING_LIST])

        if len(updated_ip_forwarding_list_leftover) > 0:
            leftover_route[common_xe.IP_FORWARDING_LIST] = updated_ip_forwarding_list_leftover
        elif common_xe.IP_FORWARDING_LIST in leftover_route:
            del leftover_route[common_xe.IP_FORWARDING_LIST]
    if common_xe.INTF_LIST in leftover_route:
        updated_intf_list_leftover = get_updated_configs(leftover_route[common_xe.INTF_LIST])

        if len(updated_intf_list_leftover) > 0:
            leftover_route[common_xe.INTF_LIST] = updated_intf_list_leftover
        elif common_xe.INTF_LIST in leftover_route:
            del leftover_route[common_xe.INTF_LIST]
    if common_xe.IP_INTF_FORWARDING_LIST in leftover_route:
        updated_ip_intf_forwarding_list_leftover = get_updated_configs(leftover_route[common_xe.IP_INTF_FORWARDING_LIST])

        if len(updated_ip_intf_forwarding_list_leftover) > 0:
            leftover_route[common_xe.IP_INTF_FORWARDING_LIST] = updated_ip_intf_forwarding_list_leftover
        elif common_xe.IP_INTF_FORWARDING_LIST in leftover_route:
            del leftover_route[common_xe.IP_INTF_FORWARDING_LIST]
    if "name" in leftover_route and len(leftover_route) < 2:
        del leftover_route["name"]

def get_updated_configs(list_leftover):
    updated_static_list = []

    for item in list_leftover:
        if item:
            updated_static_list.append(item)

    return updated_static_list

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
        from package_nso_to_oc.xe import xe_static_route
        from package_nso_to_oc import common
    else:
        import common_xe
        import xe_ospfv2
        import xe_static_route
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
        from package_nso_to_oc.xe import xe_static_route
        from package_nso_to_oc import common
    else:
        from xe import common_xe
        from xe import xe_ospfv2
        from xe import xe_static_route
        import common
