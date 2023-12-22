#! /usr/bin/env python3
"""
This script is used by xr_network_instances.py to translate static route configs from NED to OC.
"""

import copy
from importlib.util import find_spec

if (find_spec("package_nso_to_oc") is not None):
    from package_nso_to_oc import common
    from package_nso_to_oc.xr import common_xr
else:
    import common
    from xr import common_xr

xr_routes_notes = []


def configure_xr_static_routes(net_inst, vrf_forwarding_list, config_leftover, network_instances_notes):
    instance_name = net_inst["openconfig-network-instance:name"]
    net_protocols = net_inst["openconfig-network-instance:protocols"]["openconfig-network-instance:protocol"]
    static_route = get_static_protocol(net_protocols)["openconfig-network-instance:static-routes"][
        "openconfig-network-instance:static"]

    for index, route_forwarding in enumerate(vrf_forwarding_list[common_xr.IP_FORWARDING_LIST]):
        process_static_routes(route_forwarding, static_route)
    for index, route_forwarding in enumerate(vrf_forwarding_list[common_xr.INTF_LIST]):
        process_static_routes(route_forwarding, static_route)
    for index, route_forwarding in enumerate(vrf_forwarding_list[common_xr.IP_INTF_FORWARDING_LIST]):
        process_static_routes(route_forwarding, static_route)

    network_instances_notes += xr_routes_notes


def process_static_routes(route_forwarding, static_route):
    new_static_route = configure_static_route(route_forwarding)

    if new_static_route:
        static_route.append(new_static_route)


def get_static_protocol(net_protocols):
    static_protocol = {
        "openconfig-network-instance:identifier": "STATIC",
        "openconfig-network-instance:name": "DEFAULT"
    }
    static_list_template = {"openconfig-network-instance:static": []}

    for net_protocol in net_protocols:
        if net_protocol.get("openconfig-network-instance:identifier", "") == "STATIC":
            if not "openconfig-network-instance:config" in net_protocol:
                net_protocol["openconfig-network-instance:config"] = copy.deepcopy(static_protocol)
            if not "openconfig-network-instance:static-routes" in net_protocol:
                net_protocol["openconfig-network-instance:static-routes"] = copy.deepcopy(static_list_template)

            return net_protocol

    static_protocol["openconfig-network-instance:config"] = copy.deepcopy(static_protocol)
    static_protocol["openconfig-network-instance:static-routes"] = copy.deepcopy(static_list_template)
    net_protocols.append(static_protocol)

    return static_protocol


def configure_static_route(route_forwarding):
    new_static_route = {
        "openconfig-network-instance:prefix": route_forwarding.get("net"),
        "openconfig-network-instance:config": {
            "openconfig-network-instance:prefix": route_forwarding.get("net")
        },
        "openconfig-network-instance:next-hops": {
            "openconfig-network-instance:next-hop": []
        }
    }

    if "name" in route_forwarding:
        new_static_route["openconfig-network-instance:config"]["openconfig-network-instance:description"] = \
        route_forwarding["name"]
    if "tag" in route_forwarding:
        new_static_route["openconfig-network-instance:config"]["openconfig-network-instance:set-tag"] = \
        route_forwarding["tag"]

    new_index = configure_next_hop_index(route_forwarding)
    new_static_route["openconfig-network-instance:next-hops"]["openconfig-network-instance:next-hop"].append(new_index)

    return new_static_route


def configure_next_hop_index(route_forwarding):
    new_index = {}

    if {"interface", "address"} <= route_forwarding.keys():
        (intf_type, intf_num_full) = common.get_interface_type_number_and_subinterface(route_forwarding["interface"])
        (intf_num, sub_intf_num) = common.get_interface_number_split(intf_num_full)
        new_index["openconfig-network-instance:index"] = f"{intf_type}{intf_num}"
        new_index["openconfig-network-instance:config"] = {
            "openconfig-network-instance:index": f"{intf_type}{intf_num}",
            "openconfig-network-instance:next-hop": route_forwarding["address"]
        }
        new_index["openconfig-network-instance:interface-ref"] = {
            "openconfig-network-instance:config": {
                "openconfig-network-instance:interface": f"{intf_type}{intf_num}"
            }
        }
        if (intf_type != "Tunnel") and (intf_type != "Vlan"):
            new_index["openconfig-network-instance:interface-ref"]["openconfig-network-instance:config"][
                "openconfig-network-instance:subinterface"] = sub_intf_num
    elif "address" in route_forwarding:
        new_index["openconfig-network-instance:index"] = route_forwarding["address"]
        new_index["openconfig-network-instance:config"] = {
            "openconfig-network-instance:index": route_forwarding["address"],
            "openconfig-network-instance:next-hop": route_forwarding["address"]
        }
    elif "interface" in route_forwarding:
        if route_forwarding["interface"] == "Null0":
            new_index["openconfig-network-instance:index"] = "DROP"
            new_index["openconfig-network-instance:config"] = {
                "openconfig-network-instance:index": "DROP",
                "openconfig-network-instance:next-hop": "DROP"
            }
        elif route_forwarding["interface"] == "dhcp":
            new_index["openconfig-network-instance:index"] = "DHCP"
            new_index["openconfig-network-instance:config"] = {
                "openconfig-network-instance:index": "DHCP",
                "openconfig-network-instance:next-hop": "DHCP"
            }
        else:
            (intf_type, intf_num_full) = common.get_interface_type_number_and_subinterface(
                route_forwarding["interface"])
            (intf_num, sub_intf_num) = common.get_interface_number_split(intf_num_full)
            new_index["openconfig-network-instance:index"] = f"{intf_type}{intf_num}"
            new_index["openconfig-network-instance:config"] = {
                "openconfig-network-instance:index": f"{intf_type}{intf_num}",
                "openconfig-network-instance:next-hop": "LOCAL_LINK",
                "openconfig-local-routing-ext:dhcp-learned": "ENABLE" if "dhcp" in route_forwarding else "DISABLE"
            }
            new_index["openconfig-network-instance:interface-ref"] = {
                "openconfig-network-instance:config": {
                    "openconfig-network-instance:interface": f"{intf_type}{intf_num}"
                }
            }
            if (intf_type != "Tunnel") and (intf_type != "Vlan"):
                new_index["openconfig-network-instance:interface-ref"]["openconfig-network-instance:config"][
                    "openconfig-network-instance:subinterface"] = sub_intf_num

    if "metric" in route_forwarding:
        new_index["openconfig-network-instance:config"]["openconfig-network-instance:metric"] = route_forwarding[
            "metric"]

    return new_index
