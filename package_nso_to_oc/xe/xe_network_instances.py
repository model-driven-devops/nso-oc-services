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


def generate_list_indexes_to_delete(a_list: list, greatest_length: int) -> list:
    delete_indexes = []
    for i in a_list:
        if len(i) <= greatest_length:
            delete_indexes.append(a_list.index(i))
    delete_indexes.sort(reverse=True)
    return delete_indexes


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
                if vrf.get("description"):
                    temp_vrf["openconfig-network-instance:config"]["openconfig-network-instance:description"] = vrf.get(
                        "description")
                    del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["description"]
                del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["address-family"]
            openconfig_network_instances["openconfig-network-instance:network-instances"][
                "openconfig-network-instance:network-instance"].append(temp_vrf)
        # Clean up VRF remaining
        indexes_to_remove = generate_list_indexes_to_delete(
            config_leftover.get("tailf-ned-cisco-ios:vrf", {}).get("definition", []), 1)
        if indexes_to_remove:
            for vrf_index in indexes_to_remove:
                del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]
        if not config_leftover["tailf-ned-cisco-ios:vrf"]["definition"]:
            del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"]
        if len(config_leftover["tailf-ned-cisco-ios:vrf"]) == 0:
            del config_leftover["tailf-ned-cisco-ios:vrf"]
    interfaces_by_vrf = get_interfaces_by_vrf(config_before)
    route_forwarding_list_by_vrf = get_route_forwarding_list_by_vrf(config_before)
    configure_network_instances(config_before, config_leftover, interfaces_by_vrf, route_forwarding_list_by_vrf)

    if type(config_before.get("tailf-ned-cisco-ios:ip", {}).get("multicast-routing", {}).get("distributed", '')) is list:
        configure_pim_network_instance(config_before, config_leftover)
        configure_igmp_network_instance(config_before, config_leftover)
        configure_cgmp_network_instance(config_before, config_leftover)

    cleanup_null_ospf_leftovers(config_leftover)
    cleanup_null_static_route_leftovers(config_leftover)
    cleanup_null_bgp_leftovers(config_before, config_leftover)


def get_interfaces_by_vrf(config_before):
    interfaces_by_vrf = {}
    interfaces = config_before.get("tailf-ned-cisco-ios:interface", {})
    for interface_type, interface_list in interfaces.items():
        if interface_type == "Port-channel-subinterface":
            interface_type = "Port-channel"
            interface_list = interface_list[interface_type]

        for interface in interface_list:
            if (not "ip" in interface or not "address" in interface["ip"]
                    or not "primary" in interface["ip"]["address"] or not "address" in interface["ip"]["address"][
                        "primary"]):
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

def build_router_ospf_by_vrf(config_before):
    router_ospf_by_vrf = {}

    for index, ospf in enumerate(config_before.get("tailf-ned-cisco-ios:router", {}).get("ospf", [])):
        if "vrf" in ospf:
            vrf_name = ospf["vrf"]
        else:
            vrf_name = "default"

        if not vrf_name in router_ospf_by_vrf:
            router_ospf_by_vrf[vrf_name] = []

        router_ospf_by_vrf[vrf_name].append(index)
        
    return router_ospf_by_vrf

def configure_network_instances(config_before, config_leftover, interfaces_by_vrf, route_forwarding_list_by_vrf):
    router_ospf_by_vrf = build_router_ospf_by_vrf(config_before)

    for net_inst in openconfig_network_instances["openconfig-network-instance:network-instances"][
        "openconfig-network-instance:network-instance"]:
        configure_network_interfaces(net_inst, interfaces_by_vrf)

        if len(interfaces_by_vrf.get(net_inst["openconfig-network-instance:name"], [])) > 0:
            vrf_interfaces = interfaces_by_vrf.get(net_inst["openconfig-network-instance:name"])
            xe_ospfv2.configure_xe_ospf(net_inst, vrf_interfaces, config_before, config_leftover, 
                                        network_instances_notes)
        if len(route_forwarding_list_by_vrf.get(net_inst["openconfig-network-instance:name"], [])) > 0:
            vrf_forwarding_list = route_forwarding_list_by_vrf.get(net_inst["openconfig-network-instance:name"])
            xe_static_route.configure_xe_static_routes(net_inst, vrf_forwarding_list, config_leftover,
                                                       network_instances_notes)
        
        xe_ospfv2.configure_xe_ospf_redistribution(net_inst, config_before, config_leftover, router_ospf_by_vrf)
        xe_bgp.configure_xe_bgp(net_inst, config_before, config_leftover, network_instances_notes)
        xe_bgp.configure_xe_bgp_redistribution(net_inst, config_before, config_leftover)
        xe_mpls.configure_xe_mpls(net_inst, config_before, config_leftover, network_instances_notes)


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

        net_inst["openconfig-network-instance:interfaces"]["openconfig-network-instance:interface"].append(
            new_interface)


def configure_pim_network_instance(config_before, config_leftover):
    """
    Translates NSO XE NED to MDD OpenConfig Network Instance for IP multicast and interface PIM configuration
    """

    pim_protocol_by_networkinstance = {}

    pim_protocol_instance = {
        "openconfig-network-instance:identifier": "PIM",
        "openconfig-network-instance:name": "PIM",
        "openconfig-network-instance:config": {
            "openconfig-network-instance:identifier": "PIM",
            "openconfig-network-instance:name": "PIM",
            "openconfig-network-instance:enabled": True,
            "openconfig-network-instance:default-metric": 1
        },
        "openconfig-network-instance:pim": {
            "openconfig-network-instance:interfaces": {
                "openconfig-network-instance:interface": [
                ]
            }
        }
    }
    pim_interface = {
        "openconfig-network-instance:interface-id": "",
        "openconfig-network-instance:config": {
            "openconfig-network-instance:enabled": "",
            "openconfig-network-instance:interface-id": "",
            "openconfig-network-instance:mode": "",
            "openconfig-network-instance:dr-priority": 0,
            "openconfig-network-instance:hello-interval": 0,
            "openconfig-pim-ext:neighbor-filter": ""
        },
        "openconfig-network-instance:interface-ref": {
            "openconfig-network-instance:config": {
                "openconfig-network-instance:interface": "",
                "openconfig-network-instance:subinterface": ""
            }
        }
    }

    for interface_type in config_before.get("tailf-ned-cisco-ios:interface", {}):
        for nso_index, value in enumerate(config_before["tailf-ned-cisco-ios:interface"][interface_type]):
            tmp_pim_interface = copy.deepcopy(pim_interface)
            if value.get("ip", {}).get("pim", {}):
                int_num = str(value['name']).split(".")[0]
                subint_num = 0
                if "." in str(value['name']):
                    subint_num = value['name'].split(".")[1]

                tmp_pim_interface["openconfig-network-instance:interface-id"] = int_num
                tmp_pim_interface["openconfig-network-instance:config"]["openconfig-network-instance:enabled"] = True
                tmp_pim_interface["openconfig-network-instance:config"]["openconfig-network-instance:interface-id"] = int_num
                tmp_pim_interface["openconfig-network-instance:interface-ref"]["openconfig-network-instance:config"]["openconfig-network-instance:interface"] = interface_type + int_num
                tmp_pim_interface["openconfig-network-instance:interface-ref"]["openconfig-network-instance:config"]["openconfig-network-instance:subinterface"] = subint_num

                for pim_key, pim_value in value.get("ip", {}).get("pim", {}).items():
                    if "dr-priority" in pim_key:
                        tmp_pim_interface["openconfig-network-instance:config"]["openconfig-network-instance:dr-priority"] = pim_value
                    if "query-interval" in pim_key:
                        tmp_pim_interface["openconfig-network-instance:config"]["openconfig-network-instance:hello-interval"] = pim_value
                    if "neighbor-filter" in pim_key:
                        tmp_pim_interface["openconfig-network-instance:config"]["openconfig-pim-ext:neighbor-filter"] = str(pim_value)
                    if "mode" in pim_key:
                        if "sparse-dense-mode" in pim_value:
                            tmp_pim_interface["openconfig-network-instance:config"]["openconfig-network-instance:mode"] = "openconfig-pim-types:PIM_MODE_DENSE"
                        elif "sparse-mode" in pim_value:
                            tmp_pim_interface["openconfig-network-instance:config"]["openconfig-network-instance:mode"] = "openconfig-pim-types:PIM_MODE_SPARSE"

                if value.get("vrf", {}).get("forwarding", {}):
                    vrf_name = value["vrf"]["forwarding"]
                    if pim_protocol_by_networkinstance.get(vrf_name) is None:
                        pim_protocol_by_networkinstance[vrf_name] = {}
                        tmp_pim_protocol_instance = copy.deepcopy(pim_protocol_instance)
                        pim_protocol_by_networkinstance.update({vrf_name : tmp_pim_protocol_instance})
                else:
                    vrf_name = "default"
                    if pim_protocol_by_networkinstance.get(vrf_name) is None:
                        pim_protocol_by_networkinstance[vrf_name] = {}
                        tmp_pim_protocol_instance = copy.deepcopy(pim_protocol_instance)
                        pim_protocol_by_networkinstance.update({vrf_name : tmp_pim_protocol_instance})

                pim_protocol_by_networkinstance[vrf_name]["openconfig-network-instance:pim"]["openconfig-network-instance:interfaces"]["openconfig-network-instance:interface"].append(tmp_pim_interface)

                del config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index]["ip"]["pim"]

    if "multicast-routing" in config_leftover.get("tailf-ned-cisco-ios:ip", {}):
        del config_leftover["tailf-ned-cisco-ios:ip"]["multicast-routing"]

    for instance_name, network_instance in pim_protocol_by_networkinstance.items():
        index = 0
        for oc_name in openconfig_network_instances["openconfig-network-instance:network-instances"]["openconfig-network-instance:network-instance"]:
            for oc_instance, oc_instance_name in oc_name.items():
                if oc_instance_name == instance_name:
                    openconfig_network_instances["openconfig-network-instance:network-instances"]["openconfig-network-instance:network-instance"][index]["openconfig-network-instance:protocols"]["openconfig-network-instance:protocol"].append(network_instance)
            index += 1


def configure_igmp_network_instance(config_before, config_leftover):
    """
    Translates NSO XE NED to MDD OpenConfig Network Instance for IP multicast and interface IGMP configuration
    """

    igmp_protocol_by_networkinstance = {}

    igmp_protocol_instance = {
        "openconfig-network-instance:identifier": "IGMP",
        "openconfig-network-instance:name": "IGMP",
        "openconfig-network-instance:config": {
            "openconfig-network-instance:identifier": "IGMP",
            "openconfig-network-instance:name": "IGMP",
            "openconfig-network-instance:enabled": True,
            "openconfig-network-instance:default-metric": 1
        },
        "openconfig-network-instance:igmp": {
            "openconfig-network-instance:interfaces": {
                "openconfig-network-instance:interface": [
                ]
            }
        }
    }

    igmp_interface = {
        "openconfig-network-instance:interface-id": "",
        "openconfig-network-instance:config": {
            "openconfig-network-instance:enabled": "",
            "openconfig-network-instance:interface-id": "",
            "openconfig-network-instance:version": "",
            "openconfig-network-instance:query-interval": "",
            "openconfig-network-instance:filter-prefixes": ""
        },
        "openconfig-network-instance:interface-ref": {
            "openconfig-network-instance:config": {
                "openconfig-network-instance:interface": "",
                "openconfig-network-instance:subinterface": ""
            }
        }
    }

    for interface_type in config_before.get("tailf-ned-cisco-ios:interface", {}):
        for nso_index, value in enumerate(config_before["tailf-ned-cisco-ios:interface"][interface_type]):
            tmp_igmp_interface = copy.deepcopy(igmp_interface)
            if value.get("ip", {}).get("igmp", {}):
                int_num = str(value['name']).split(".")[0]
                subint_num = 0
                if "." in str(value['name']):
                    subint_num = value['name'].split(".")[1]

                tmp_igmp_interface["openconfig-network-instance:interface-id"] = int_num
                tmp_igmp_interface["openconfig-network-instance:config"]["openconfig-network-instance:enabled"] = True
                tmp_igmp_interface["openconfig-network-instance:config"]["openconfig-network-instance:interface-id"] = int_num
                tmp_igmp_interface["openconfig-network-instance:interface-ref"]["openconfig-network-instance:config"]["openconfig-network-instance:interface"] = interface_type + int_num
                tmp_igmp_interface["openconfig-network-instance:interface-ref"]["openconfig-network-instance:config"]["openconfig-network-instance:subinterface"] = subint_num

                for igmp_key, igmp_value in value.get("ip", {}).get("igmp", {}).items():
                    if "version" in igmp_key:
                        tmp_igmp_interface["openconfig-network-instance:config"]["openconfig-network-instance:version"] = igmp_value
                    if "query-interval" in igmp_key:
                        tmp_igmp_interface["openconfig-network-instance:config"]["openconfig-network-instance:query-interval"] = igmp_value
                    if "access-group" in igmp_key:
                        tmp_igmp_interface["openconfig-network-instance:config"]["openconfig-network-instance:filter-prefixes"] = igmp_value

                if value.get("vrf", {}).get("forwarding", {}):
                    vrf_name = value["vrf"]["forwarding"]
                    if igmp_protocol_by_networkinstance.get(vrf_name) is None:
                        igmp_protocol_by_networkinstance[vrf_name] = {}
                        tmp_igmp_protocol_instance = copy.deepcopy(igmp_protocol_instance)
                        igmp_protocol_by_networkinstance.update({vrf_name : tmp_igmp_protocol_instance})
                else:
                    vrf_name = "default"
                    if igmp_protocol_by_networkinstance.get(vrf_name) is None:
                        igmp_protocol_by_networkinstance[vrf_name] = {}
                        tmp_igmp_protocol_instance = copy.deepcopy(igmp_protocol_instance)
                        igmp_protocol_by_networkinstance.update({vrf_name : tmp_igmp_protocol_instance})

                igmp_protocol_by_networkinstance[vrf_name]["openconfig-network-instance:igmp"]["openconfig-network-instance:interfaces"]["openconfig-network-instance:interface"].append(tmp_igmp_interface)

                del config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index]["ip"]["igmp"]

    if "multicast-routing" in config_leftover.get("tailf-ned-cisco-ios:ip", {}):
        del config_leftover["tailf-ned-cisco-ios:ip"]["multicast-routing"]

    for instance_name, network_instance in igmp_protocol_by_networkinstance.items():
        index = 0
        for oc_name in openconfig_network_instances["openconfig-network-instance:network-instances"]["openconfig-network-instance:network-instance"]:
            for oc_instance, oc_instance_name in oc_name.items():
                if oc_instance_name == instance_name:
                    openconfig_network_instances["openconfig-network-instance:network-instances"]["openconfig-network-instance:network-instance"][index]["openconfig-network-instance:protocols"]["openconfig-network-instance:protocol"].append(network_instance)
            index += 1


def configure_cgmp_network_instance(config_before, config_leftover):
    """
    Translates NSO XE NED to MDD OpenConfig Network Instance for IP multicast and interface CGMP configuration
    """

    cgmp_protocol_by_networkinstance = {}

    cgmp_protocol_instance = {
        "openconfig-network-instance:identifier": "CGMP",
        "openconfig-network-instance:name": "CGMP",
        "openconfig-network-instance:config": {
            "openconfig-network-instance:identifier": "CGMP",
            "openconfig-network-instance:name": "CGMP",
            "openconfig-network-instance:enabled": True,
            "openconfig-network-instance:default-metric": 1
        },
        "openconfig-network-instance:cgmp": {
            "openconfig-network-instance:interfaces": {
                "openconfig-network-instance:interface": [
                ]
            }
        }
    }

    cgmp_interface = {
        "openconfig-network-instance:interface-id": "",
        "openconfig-network-instance:config": {
            "openconfig-network-instance:enabled": "",
            "openconfig-network-instance:interface-id": "",
            "openconfig-network-instance:cgmp-options": "NOT_APPLICABLE",
        },
        "openconfig-network-instance:interface-ref": {
            "openconfig-network-instance:config": {
                "openconfig-network-instance:interface": "",
                "openconfig-network-instance:subinterface": ""
            }
        }
    }

    for interface_type in config_before.get("tailf-ned-cisco-ios:interface", {}):
        for nso_index, value in enumerate(config_before["tailf-ned-cisco-ios:interface"][interface_type]):
            tmp_cgmp_interface = copy.deepcopy(cgmp_interface)
            if type(value.get("ip", {}).get("cgmp", '')) is dict:
                int_num = str(value['name']).split(".")[0]
                subint_num = 0
                if "." in str(value['name']):
                    subint_num = value['name'].split(".")[1]

                tmp_cgmp_interface["openconfig-network-instance:interface-id"] = int_num
                tmp_cgmp_interface["openconfig-network-instance:config"]["openconfig-network-instance:enabled"] = True
                tmp_cgmp_interface["openconfig-network-instance:config"]["openconfig-network-instance:interface-id"] = int_num
                tmp_cgmp_interface["openconfig-network-instance:interface-ref"]["openconfig-network-instance:config"]["openconfig-network-instance:interface"] = interface_type + int_num
                tmp_cgmp_interface["openconfig-network-instance:interface-ref"]["openconfig-network-instance:config"]["openconfig-network-instance:subinterface"] = subint_num

                if value.get("vrf", {}).get("forwarding", {}):
                    vrf_name = value["vrf"]["forwarding"]
                    if cgmp_protocol_by_networkinstance.get(vrf_name) is None:
                        cgmp_protocol_by_networkinstance[vrf_name] = {}
                        tmp_cgmp_protocol_instance = copy.deepcopy(cgmp_protocol_instance)
                        cgmp_protocol_by_networkinstance.update({vrf_name : tmp_cgmp_protocol_instance})
                else:
                    vrf_name = "default"
                    if cgmp_protocol_by_networkinstance.get(vrf_name) is None:
                        cgmp_protocol_by_networkinstance[vrf_name] = {}
                        tmp_cgmp_protocol_instance = copy.deepcopy(cgmp_protocol_instance)
                        cgmp_protocol_by_networkinstance.update({vrf_name : tmp_cgmp_protocol_instance})

                cgmp_protocol_by_networkinstance[vrf_name]["openconfig-network-instance:cgmp"]["openconfig-network-instance:interfaces"]["openconfig-network-instance:interface"].append(tmp_cgmp_interface)

                del config_leftover["tailf-ned-cisco-ios:interface"][interface_type][nso_index]["ip"]["cgmp"]

    if "multicast-routing" in config_leftover.get("tailf-ned-cisco-ios:ip", {}):
        del config_leftover["tailf-ned-cisco-ios:ip"]["multicast-routing"]

    for instance_name, network_instance in cgmp_protocol_by_networkinstance.items():
        index = 0
        for oc_name in openconfig_network_instances["openconfig-network-instance:network-instances"]["openconfig-network-instance:network-instance"]:
            for oc_instance, oc_instance_name in oc_name.items():
                if oc_instance_name == instance_name:
                    openconfig_network_instances["openconfig-network-instance:network-instances"]["openconfig-network-instance:network-instance"][index]["openconfig-network-instance:protocols"]["openconfig-network-instance:protocol"].append(network_instance)
            index += 1

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

        # IPv4 RT import and export policies
        temp_policies = {
            "openconfig-network-instance:inter-instance-policies": {
                "openconfig-network-instance:apply-policy": {
                    "openconfig-network-instance:config": {
                        "openconfig-network-instance:export-policy": [],
                        "openconfig-network-instance:import-policy": []}}}}
        if vrf.get("address-family", {}).get("ipv4", {}).get("import", {}).get("ipv4", {}).get("unicast", {}).get(
                "map"):
            temp_policies["openconfig-network-instance:inter-instance-policies"][
                "openconfig-network-instance:apply-policy"]["openconfig-network-instance:config"][
                "openconfig-network-instance:import-policy"].append(
                vrf.get("address-family", {}).get("ipv4", {}).get("import", {}).get("ipv4", {}).get("unicast", {}).get(
                    "map"))
            del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["address-family"]["ipv4"]["import"]
        if vrf.get("address-family", {}).get("ipv4", {}).get("export", {}).get("map"):
            temp_policies["openconfig-network-instance:inter-instance-policies"][
                "openconfig-network-instance:apply-policy"]["openconfig-network-instance:config"][
                "openconfig-network-instance:export-policy"].append(
                vrf.get("address-family", {}).get("ipv4", {}).get("export", {}).get("map"))
            del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["address-family"]["ipv4"]["export"]
        if "ipv4" in vrf.get("address-family", {}) and len(vrf.get("address-family", {}).get("ipv4", {"1": "1"})) == 0:
            del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["address-family"]["ipv4"]
        temp_vrf.update(temp_policies)
        # TODO IPv6 RT import and export policies


def process_rt(temp_vrf, vrf, rt_type):
    for rt in vrf["route-target"].get(rt_type, []):
        if "asn-ip" in rt:
            temp_vrf["openconfig-network-instance:config"][
                f"openconfig-network-instance-ext:route-targets-{rt_type}"].append(rt["asn-ip"])


def cleanup_null_ospf_leftovers(config_leftover):
    ospf_leftover = config_leftover.get("tailf-ned-cisco-ios:router", {}).get("ospf", [])
    updated_ospf_list = []

    for ospf_index in range(len(ospf_leftover)):
        cleanup_network_statements(ospf_leftover[ospf_index])
        cleanup_neighbors(ospf_leftover[ospf_index])
        cleanup_traffic_area(ospf_leftover[ospf_index])
        cleanup_virtual_link(ospf_leftover[ospf_index])

        if len(ospf_leftover[ospf_index]) > 0:
            updated_ospf_list.append(ospf_leftover[ospf_index])

    if len(updated_ospf_list) > 0:
        config_leftover.get("tailf-ned-cisco-ios:router", {})["ospf"] = updated_ospf_list
    elif "ospf" in config_leftover.get("tailf-ned-cisco-ios:router", {}):
        del config_leftover["tailf-ned-cisco-ios:router"]["ospf"]


def cleanup_network_statements(ospf_leftover):
    if "network" in ospf_leftover:
        del ospf_leftover["network"]


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

    if "route" in config_leftover.get("tailf-ned-cisco-ios:ip", {}) and len(
            config_leftover["tailf-ned-cisco-ios:ip"]["route"]) == 0:
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
        updated_ip_intf_forwarding_list_leftover = get_updated_configs(
            leftover_route[common_xe.IP_INTF_FORWARDING_LIST])

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


def cleanup_null_bgp_leftovers(config_before, config_leftover):
    bgp_before_list = config_before.get("tailf-ned-cisco-ios:router", {"bgp": []}).get("bgp")
    bgp_leftover_list = config_leftover.get("tailf-ned-cisco-ios:router", {"bgp": []}).get("bgp")

    if bgp_leftover_list == None or len(bgp_leftover_list) == 0:
        return

    bgp_before = bgp_before_list[0]
    bgp_leftover = bgp_leftover_list[0]

    clean_up_default_neighbors_and_peers(bgp_before, bgp_leftover)
    clean_up_vrf_neighbors_and_peers(bgp_before.get("address-family", {}).get("with-vrf", {}),
                                     bgp_leftover.get("address-family", {}).get("with-vrf", {}).get("ipv4", []))

    if bgp_leftover != None and bgp_leftover.get("bgp") != None:
        del bgp_leftover["bgp"]

    # if bgp_leftover != None and len(bgp_leftover["bgp"]) == 0:
    #     del bgp_leftover["bgp"]
    # if bgp_leftover.get("address-family", {}).get("ipv4") != None:
    #     check_delete_protocol_leftovers(bgp_leftover, "ipv4")
    # if bgp_leftover.get("address-family") != None:
    #     check_delete_protocol_leftovers(bgp_leftover, "vpnv4")
    # if bgp_leftover.get("address-family") != None:
    #     pass


def clean_up_default_neighbors_and_peers(bgp_before, bgp_leftover):
    delete_peers_and_neighbors(bgp_leftover)
    updated_ipv4_list = []
    updated_vpnv4_list = []

    for ipv4_index, afi_ipv4 in enumerate(bgp_before.get("address-family", {}).get("ipv4", [])):
        if afi_ipv4.get("af") == "unicast":
            delete_peers_and_neighbors(bgp_leftover["address-family"]["ipv4"][ipv4_index])
        if (bgp_leftover["address-family"]["ipv4"][ipv4_index]
                and len(bgp_leftover["address-family"]["ipv4"][ipv4_index]) > 0):
            updated_ipv4_list.append(bgp_leftover["address-family"]["ipv4"][ipv4_index])
    for vpnv4_index, afi_vpnv4 in enumerate(bgp_before.get("address-family", {}).get("vpnv4", [])):
        if afi_vpnv4.get("af") == "unicast":
            delete_peers_and_neighbors(bgp_leftover["address-family"]["vpnv4"][vpnv4_index])
        if len(bgp_leftover["address-family"]["vpnv4"][vpnv4_index]) > 0:
            updated_vpnv4_list.append(bgp_leftover["address-family"]["vpnv4"][vpnv4_index])

    # Device may not be using MP-BGP
    if bgp_before.get("address-family", {}).get("ipv4"):
        bgp_leftover["address-family"]["ipv4"] = updated_ipv4_list
    if bgp_before.get("address-family", {}).get("vpnv4"):
        bgp_leftover["address-family"]["vpnv4"] = updated_vpnv4_list


def clean_up_vrf_neighbors_and_peers(afi_vrf, afi_vrf_leftover):
    for index, afi_ipv4 in enumerate(afi_vrf.get("ipv4", [])):
        if afi_ipv4.get("af") == "unicast":
            updated_vrf_list = []

            for vrf_index, afi_ipv4_vrf in enumerate(afi_ipv4.get("vrf", [])):
                afi_vrf_ipv4_leftover = afi_vrf_leftover[index]["vrf"][vrf_index]
                delete_peers_and_neighbors(afi_vrf_ipv4_leftover)

                if len(afi_vrf_ipv4_leftover) == 0:
                    afi_vrf_leftover[index]["vrf"][vrf_index] = None
                else:
                    updated_vrf_list.append(afi_vrf_ipv4_leftover)

            afi_vrf_leftover[index]["vrf"] = updated_vrf_list


def delete_peers_and_neighbors(peer_neighbor_list_leftover):
    is_peers_present = (peer_neighbor_list_leftover != None
                        and peer_neighbor_list_leftover.get("neighbor-tag") != None
                        and peer_neighbor_list_leftover["neighbor-tag"].get("neighbor") != None)
    is_neighbors_present = (peer_neighbor_list_leftover != None
                            and peer_neighbor_list_leftover.get("neighbor") != None)
    remove_bgp_nulls(peer_neighbor_list_leftover, is_peers_present, is_neighbors_present)

    if is_peers_present and len(peer_neighbor_list_leftover["neighbor-tag"]["neighbor"]) == 0:
        del peer_neighbor_list_leftover["neighbor-tag"]
    if is_neighbors_present and len(peer_neighbor_list_leftover["neighbor"]) == 0:
        del peer_neighbor_list_leftover["neighbor"]


def remove_bgp_nulls(peer_neighbor_list_leftover, is_peers_present, is_neighbors_present):
    updated_peers = []
    updated_neighbors = []

    if is_peers_present:
        for peer in peer_neighbor_list_leftover["neighbor-tag"]["neighbor"]:
            if peer != None:
                updated_peers.append(peer)

        peer_neighbor_list_leftover["neighbor-tag"]["neighbor"] = updated_peers
    if is_neighbors_present:
        for neighbor in peer_neighbor_list_leftover["neighbor"]:
            if neighbor != None:
                updated_neighbors.append(neighbor)

        peer_neighbor_list_leftover["neighbor"] = updated_neighbors


def check_delete_protocol_leftovers(bgp_leftover, protocol):
    is_ipv4_empty = True

    for ipv4_item in bgp_leftover.get("address-family", {}).get(protocol, []):
        if ipv4_item != None and len(ipv4_item) > 0:
            is_ipv4_empty = False

    if is_ipv4_empty:
        del bgp_leftover["address-family"][protocol]


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
        from package_nso_to_oc.xe import xe_bgp
        from package_nso_to_oc.xe import xe_mpls
        from package_nso_to_oc import common
    else:
        import common_xe
        import xe_ospfv2
        import xe_static_route
        import xe_bgp
        import xe_mpls
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
        from package_nso_to_oc.xe import xe_bgp
        from package_nso_to_oc.xe import xe_mpls
        from package_nso_to_oc import common
    else:
        from xe import common_xe
        from xe import xe_ospfv2
        from xe import xe_static_route
        from xe import xe_bgp
        from xe import xe_mpls
        import common
