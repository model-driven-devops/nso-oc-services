#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_network_instances.json,
save the NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_ned_configuration_remaining_network_instances.json, and save the MDD OpenConfig configuration to a file
named {nso_device}_openconfig_network_instances.json.

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
import copy
import ipaddress

ospf_network_types = {
    "broadcast": "BROADCAST_NETWORK",
    "point-to-point": "POINT_TO_POINT_NETWORK",
    "non-broadcast": "NON_BROADCAST_NETWORK"
}

def configure_xe_ospf(net_inst, vrf_interfaces, config_before, config_leftover):
    """
    Translates NSO XE NED to MDD OpenConfig Network Instances
    """
    instance_type = net_inst["openconfig-network-instance:config"]["openconfig-network-instance:type"]
    net_protocols = net_inst["openconfig-network-instance:protocols"]["openconfig-network-instance:protocol"]
    ospf_list = config_before.get("tailf-ned-cisco-ios:router", {}).get("ospf")

    if ospf_list == None:
        return

    for ospf_index, ospf in enumerate(ospf_list):
        if ((instance_type == "L3VRF" and "vrf" in ospf)
            or (instance_type == "DEFAULT_INSTANCE" and not "vrf" in ospf)):
            process_ospf(net_protocols, vrf_interfaces, config_before, config_leftover, ospf_index, ospf)

def get_interfaces_by_area(network_statements, vrf_interfaces):
    """
    Assigns OSPF enabled interfaces by area, based on OSPF network statements.
    Network statement wildcard masks are treated like ACLs to determine which interface will be attached
    to an OSPF area.
    Source: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/command/iro-cr-book/ospf-i1.html#wp2261032279

    TODO: Consider creating network statement sort algorithm
    As there can be multiple sort algorthims, some may be more specific than others and they can point to different
    OSPF areas. The more specific statements should be prioritized over the less specific ones.
    """
    processed_interfaces = set()
    interfaces_by_area = {}

    for net_stmt in network_statements:
        # Use get method for net_stmt, since it contains input values that we did not generate and cannot guarantee.
        stmt_mask = net_stmt.get("mask", "")
        area_id = net_stmt.get("area", "0")
        merged_statement_ip = binary_merge(net_stmt.get("ip", ""), net_stmt.get("mask", ""))

        for vrf_intf in vrf_interfaces:
            full_intf_name = vrf_intf["type"] + vrf_intf["name"]

            if (full_intf_name in processed_interfaces):
                continue

            merged_vrf_intf_ip = binary_merge(vrf_intf["ip"]["address"]["primary"]["address"], stmt_mask)
            
            if merged_statement_ip == merged_vrf_intf_ip:
                # If there's a match, then this interface is OSPF enabled
                processed_interfaces.add(full_intf_name)
                
                if not area_id in interfaces_by_area:
                    interfaces_by_area[area_id] = []
                
                interfaces_by_area[area_id].append(vrf_intf)

    return interfaces_by_area

def binary_merge(ip, mask):
    """
    Transform the IPs into binary string format and merge the binary strings via OR operation
    """
    merged_result = []
    ip_in_binary = get_binary_str(ip)
    mask_in_binary = get_binary_str(mask)

    for index in range(len(ip_in_binary)):
        ip_val = ip_in_binary[index] == '1'
        mask_val = mask_in_binary[index] == '1'
        merged_result.append('1' if ip_val or mask_val else '0')

    return ''.join(merged_result)

def get_binary_str(ip_str):
    octets = ip_str.split('.')
    binary_octets = []

    # Sanity check
    if len(octets) != 4:
        raise ValueError("Invalid IP string provided")

    for octet in octets:
        binary_octets.append(format(int(octet), '08b'))

    return ''.join(binary_octets)

def get_ospfv2_global(net_protocols, prot_index):
    if (len(net_protocols) >= prot_index):
        if not "openconfig-network-instance:ospfv2" in net_protocols[prot_index]: 
            net_protocols[prot_index]["openconfig-network-instance:ospfv2"] = {}
        if not "global" in net_protocols[prot_index]["openconfig-network-instance:ospfv2"]:
            net_protocols[prot_index]["openconfig-network-instance:ospfv2"]["global"] = {}
        
        return net_protocols[prot_index]["openconfig-network-instance:ospfv2"]["global"]
    else:
        # Sanity check, should not occur...
        raise IndexError(f"The protocol index {prot_index} does not exist.")

def get_ospfv2_area(net_protocols, prot_index):
    if (len(net_protocols) >= prot_index):
        if not "openconfig-network-instance:ospfv2" in net_protocols[prot_index]: 
            net_protocols[prot_index]["openconfig-network-instance:ospfv2"] = {}
        if not "areas" in net_protocols[prot_index]["openconfig-network-instance:ospfv2"]:
            net_protocols[prot_index]["openconfig-network-instance:ospfv2"]["areas"] = {"area": []}
        
        return net_protocols[prot_index]["openconfig-network-instance:ospfv2"]["areas"]["area"]
    else:
        # Sanity check, should not occur...
        raise IndexError(f"The protocol index {prot_index} does not exist.")

def get_area_by_id(ospfv2_area, area_id):
    for area in ospfv2_area:
        if area["identifier"] == area_id:
            return area

    new_area = {"identifier": area_id, "config": {"identifier": area_id}}
    ospfv2_area.append(new_area)

    return new_area

def is_area_present_by_id(ospfv2_area, id):
    for area in ospfv2_area:
        if area.get("identifier", None) == id:
            return True

    return False

def get_intf_by_intf_number(intf_attr, intf_number):
    for intf in intf_attr:
        if intf["name"] == intf_number:
            return intf

def process_ospf(net_protocols, vrf_interfaces, config_before, config_leftover, ospf_index, ospf):
    ospf_leftover = config_leftover.get("tailf-ned-cisco-ios:router", {}).get("ospf")[ospf_index]
    # If we got here, we init an empty dict and append to protocol list for future use.
    net_protocols.append({})
    prot_index = len(net_protocols) - 1
    set_network_config(ospf_leftover, net_protocols, prot_index, ospf)
    set_ospf2_global_config(ospf_leftover, net_protocols, prot_index, ospf)
    set_graceful_restart_ietf(ospf_leftover, net_protocols, prot_index, ospf)
    set_vrf_lite(ospf_leftover, net_protocols, prot_index, ospf)
    set_default_info_originate(ospf_leftover, net_protocols, prot_index, ospf)
    check_areas(ospf_leftover, net_protocols, vrf_interfaces, config_before, config_leftover, prot_index, ospf)
    set_mpls_ldp_sync(ospf_leftover, net_protocols, prot_index, ospf)
    set_timers_lsa(ospf_leftover, net_protocols, prot_index, ospf)
    set_timers_spf(ospf_leftover, net_protocols, prot_index, ospf)

def set_network_config(ospf_leftover, net_protocols, prot_index, ospf):
    net_protocols[prot_index]["identifier"] = "OSPF"
    net_protocols[prot_index]["name"] = f'{ospf.get("id")}'
    temp_ospf = {"config": {
        "identifier": "OSPF",
        "name": f'{ospf.get("id")}',
        "enabled": True
    }}
    net_protocols[prot_index].update(temp_ospf)

    if ospf_leftover.get("id"):
        del ospf_leftover["id"]

def set_ospf2_global_config(ospf_leftover, net_protocols, prot_index, ospf):
    if (not ospf.get("router-id") and not ospf.get("log-adjacency-changes") 
        and not ospf.get("compatible") and not ospf.get("prefix-suppression")):
        return

    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
    ospfv2_global_config = {}

    if ospf.get("router-id"):
        ospfv2_global_config["router-id"] = f'{ospf.get("router-id")}'
        del ospf_leftover["router-id"]
    if ospf.get("log-adjacency-changes"):
        ospfv2_global_config["log-adjacency-changes"] = True
    else:
        ospfv2_global_config["log-adjacency-changes"] = False
    if ospf.get("compatible") and ospf["compatible"].get("rfc1583"):
        ospfv2_global_config["summary-route-cost-mode"] = "RFC2328_COMPATIBLE"
    else:
        ospfv2_global_config["summary-route-cost-mode"] = "RFC1583_COMPATIBLE"
    if ospf.get("prefix-suppression"):
        ospfv2_global_config["hide-transit-only-networks"] = True
    else:
        ospfv2_global_config["hide-transit-only-networks"] = False

    # Common clean up
    if "log-adjacency-changes" in ospf_leftover:
        del ospf_leftover["log-adjacency-changes"]
    if "compatible" in ospf_leftover:
        del ospf_leftover["compatible"]
    if "prefix-suppression" in ospf_leftover:
        del ospf_leftover["prefix-suppression"]

    ospfv2_global["config"] = ospfv2_global_config

def set_graceful_restart_ietf(ospf_leftover, net_protocols, prot_index, ospf):
    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
    graceful_restart_config = {"graceful-restart": {"config": {}}}

    if ospf.get("nsf-ietf") and ospf["nsf-ietf"].get("nsf") and "ietf" in ospf["nsf-ietf"]["nsf"]:
        graceful_restart_config["graceful-restart"]["config"]["enabled"] = True
        del ospf_leftover["nsf-ietf"]["nsf"]["ietf"]
    else:
        graceful_restart_config["graceful-restart"]["config"]["enabled"] = False

    ospfv2_global.update(graceful_restart_config)

def set_vrf_lite(ospf_leftover, net_protocols, prot_index, ospf):
    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
    
    if not ospfv2_global.get("config"):
        ospfv2_global["config"] = {}

    if ospf.get("capability") and "vrf-lite" in ospf["capability"]:
        ospfv2_global["config"]["openconfig-ospfv2-ext:capability-vrf-lite"] = True
        del ospf_leftover["nsf-ietf"]["nsf"]["ietf"]
    else:
        ospfv2_global["config"]["openconfig-ospfv2-ext:capability-vrf-lite"] = False

def set_default_info_originate(ospf_leftover, net_protocols, prot_index, ospf):
    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)

    if not "default-information" in ospf or not "originate" in ospf["default-information"]:
        ospfv2_global["config"] = {"openconfig-ospfv2-ext:default-information-originate": {"config": {"enabled": False }}}
        return

    if not "config" in ospfv2_global:
        ospfv2_global["config"] = {}

    oc_default_info_originate = {"openconfig-ospfv2-ext:default-information-originate": {"config": {}}}
    originate_config = oc_default_info_originate["openconfig-ospfv2-ext:default-information-originate"]["config"]
    default_info_originate = ospf["default-information"]["originate"]

    if "always" in default_info_originate:
        originate_config["always"] = True

        if "always" in ospf_leftover["default-information"]["originate"]:
            del ospf_leftover["default-information"]["originate"]["always"]
    if "metric" in default_info_originate:
        originate_config["metric"] = default_info_originate["metric"]

        if "metric" in ospf_leftover["default-information"]["originate"]:
            del ospf_leftover["default-information"]["originate"]["metric"]
    if "metric-type" in default_info_originate:
        originate_config["metric-type"] = default_info_originate["metric-type"]

        if "metric-type" in ospf_leftover["default-information"]["originate"]:
            del ospf_leftover["default-information"]["originate"]["metric-type"]
    if "route-map" in default_info_originate:
        originate_config["route-map"] = default_info_originate["route-map"]

        if "route-map" in ospf_leftover["default-information"]["originate"]:
            del ospf_leftover["default-information"]["originate"]["route-map"]

    ospfv2_global["config"].update(oc_default_info_originate)
            
def check_areas(ospf_leftover, net_protocols, vrf_interfaces, config_before, config_leftover, prot_index, ospf):
    intf_config_leftover = config_leftover.get("tailf-ned-cisco-ios:interface", {}) 
    ospfv2_area = get_ospfv2_area(net_protocols, prot_index)
    interfaces_by_area = get_interfaces_by_area(ospf.get("network", []), vrf_interfaces)

    if "area" in ospf:
        is_area_0_present = check_for_area_0(ospf)

        for area_key, area in enumerate(ospf["area"]):
            set_ospfv2_areas(ospfv2_area, area, area_key, ospf, ospf_leftover)

            if is_area_0_present and int(area["id"]) != 0:
                # We do this as long as area 0 is available and destination area is not 0.
                set_inter_area_propagation_policy(ospf_leftover, net_protocols, prot_index, area_key, area)

            for current_intf in interfaces_by_area.get(area.get("id", 0), []):
                intf_type, intf_number = (current_intf["type"], current_intf["name"])
                intf_name = intf_type + intf_number
                intf_attr_leftover = intf_config_leftover.get(intf_type, {})
                intf_leftover = get_intf_by_intf_number(intf_attr_leftover, intf_number)
                set_ospfv2_intf_areas(ospfv2_area, intf_leftover, area, intf_name, current_intf, ospf, ospf_leftover)

def check_for_area_0(ospf):
    for area in ospf["area"]:
        if area["id"] == 0:
            return True

    return False

def set_inter_area_propagation_policy(ospf_leftover, net_protocols, prot_index, area_key, area):
    if "id" in area and "filter-list" in area and len(area["filter-list"]) == 1:
        ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
        import_policy_prefix = area["filter-list"][0]["prefix"]
        service_policy = {}

        if not "inter-area-propagation-policies" in ospfv2_global:
            ospfv2_global["inter-area-propagation-policies"] = {}
        if not "inter-area-propagation-policy" in ospfv2_global["inter-area-propagation-policies"]:
            ospfv2_global["inter-area-propagation-policies"]["inter-area-propagation-policy"] = []

        # Per Steven Mosher, 0 is the implied source area, but double check again...
        service_policy["src-area"] = 0
        service_policy["dst-area"] = area["id"]
        service_policy["config"] = {
            "src-area": 0,
            "dst-area": area["id"],
            "import-policy": [import_policy_prefix]
        }

        ospfv2_global["inter-area-propagation-policies"]["inter-area-propagation-policy"].append(service_policy)
        if "filter-list" in ospf_leftover["area"][area_key]:
            del ospf_leftover["area"][area_key]["filter-list"]
    

def set_mpls_ldp_sync(ospf_leftover, net_protocols, prot_index, ospf):
    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
    is_igp_ldp_sync = "mpls" in ospf and "ldp" in ospf["mpls"] and "sync" in ospf["mpls"]["ldp"]
    ospfv2_global["mpls"] = {"igp-ldp-sync": {"config": {"enabled": is_igp_ldp_sync}}}

    if is_igp_ldp_sync:
        del ospf_leftover["mpls"]["ldp"]["sync"]

def set_timers_lsa(ospf_leftover, net_protocols, prot_index, ospf):
    if not "timers" in ospf or not "throttle" in ospf["timers"] or not "lsa" in ospf["timers"]["throttle"]:
        return

    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
    config = {}
    lsa = ospf["timers"]["throttle"]["lsa"]

    if "start-interval" in lsa or "hold-interval" in lsa or "max-interval" in lsa:
        if "start-interval" in lsa and "hold-interval" in lsa and "max-interval" in lsa:
            config["initial-delay"] = lsa["start-interval"]
            config["maximum-delay"] = lsa["max-interval"]
            config["openconfig-ospfv2-ext:hold-time"] = lsa["hold-interval"]

            if not "timers" in ospfv2_global:
                ospfv2_global["timers"] = {}
            if not "lsa-generation" in ospfv2_global["timers"]:
                ospfv2_global["timers"]["lsa-generation"] = {}
            
            ospfv2_global["timers"]["lsa-generation"].update({"config": config})
        else:
            raise ValueError("XE OSPF throttle timers lsa needs values for start-interval, hold-interval, and max-interval")

    del ospf_leftover["timers"]["throttle"]["lsa"]

def set_timers_spf(ospf_leftover, net_protocols, prot_index, ospf):
    if not "timers" in ospf or not "throttle" in ospf["timers"] or not "spf" in ospf["timers"]["throttle"]:
        return

    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
    config = {}
    spf = ospf["timers"]["throttle"]["spf"]

    if "spf-start" in spf or "spf-hold" in spf or "spf-max-wait" in spf:
        if "spf-start" in spf and "spf-hold" in spf and "spf-max-wait" in spf:
            config["initial-delay"] = spf["spf-start"]
            config["maximum-delay"] = spf["spf-max-wait"]
            config["openconfig-ospfv2-ext:hold-time"] = spf["spf-hold"]

            if not "timers" in ospfv2_global:
                ospfv2_global["timers"] = {}
            if not "spf" in ospfv2_global["timers"]:
                ospfv2_global["timers"]["spf"] = {}
            
            ospfv2_global["timers"]["spf"].update({"config": config})
        else:
            raise ValueError('XE OSPF throttle timers spf needs values for spf-start, spf-hold, and spf-max-wait')

    del ospf_leftover["timers"]["throttle"]["spf"]

def set_ospfv2_intf_areas(ospfv2_area, intf_leftover, area, intf_name, intf, ospf, ospf_leftover):
    intf_config = {"id": intf_name}
    set_network_type(intf, intf_leftover, intf_config)
    set_metric(intf, intf_leftover, intf_config)
    set_passive(ospf, ospf_leftover, intf_config, intf_name)
    set_priority(intf, intf_leftover, intf_config)
    area_intf = get_area_by_id(ospfv2_area, area["id"])

    if not "interfaces" in area_intf:
        area_intf["interfaces"] = {"interface": []}
    if not "interface" in area_intf["interfaces"]:
        area_intf["interfaces"]["interface"] = []

    area_intf["interfaces"]["interface"].append({
        "id": intf_name,
        "config": intf_config,
        "enable-bfd": {"config": {"enabled": is_bfd_enabled(intf, intf_leftover)}},
        "neighbors": set_neighbors(ospf, ospf_leftover),
        "timers": set_timers(intf, intf_leftover)
    })

def set_network_type(intf, intf_leftover, intf_config):
    if ("ip" in intf and "ospf" in intf["ip"] and "network" in intf["ip"]["ospf"] and len(intf["ip"]["ospf"]["network"]) > 0
        and intf["ip"]["ospf"]["network"][0] in ospf_network_types):
        intf_config["network-type"] = ospf_network_types[intf["ip"]["ospf"]["network"][0]]
        
        if "network" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["network"]

def set_metric(intf, intf_leftover, intf_config):
    if "ip" in intf and "ospf" in intf["ip"] and "cost" in intf["ip"]["ospf"]:
        intf_config["metric"] = intf["ip"]["ospf"]["cost"]

        if "cost" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["cost"]

def set_passive(ospf, ospf_leftover, intf_config, intf_name):
    if "passive-interface" in ospf and "interface" in ospf["passive-interface"]:
        # We're brute forcing, but we don't expect 100s of interfaces anyway...
        for passive_intf in ospf["passive-interface"]["interface"]:
            if passive_intf["name"] == intf_name:
                intf_config["passive"] = True
                break
        else:
            intf_config["passive"] = False
    
    if ("passive-interface" in ospf_leftover):
        del ospf_leftover["passive-interface"]

def set_priority(intf, intf_leftover, intf_config):
    if "ip" in intf and "ospf" in intf["ip"] and "priority" in intf["ip"]["ospf"]:
        intf_config["metric"] = intf["ip"]["ospf"]["priority"]

        if "priority" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["priority"]

def is_bfd_enabled(intf, intf_leftover):
    if "ip" in intf and "ospf" in intf["ip"] and "bfd" in intf["ip"]["ospf"]:
        if "bfd" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["bfd"]
        
        return True

    return False

def set_neighbors(ospf, ospf_leftover):
    neighbor = []
    if "neighbor" in ospf:
        for neighbor_index, ospf_neighbor in enumerate(ospf["neighbor"]):
            metric = ""
            
            if "cost-database-filter-container" in ospf_neighbor and "cost" in ospf_neighbor["cost-database-filter-container"]:
                metric = ospf_neighbor["cost-database-filter-container"]["cost"]
            
            neighbor.append({
                "router-id": ospf_neighbor.get("ip", ""),
                "config": {
                    "router-id": ospf_neighbor.get("ip", ""),
                    "metric": metric
                }
            })

            # Deleting indexes while iterating causes issues, just blank out or nullify
            ospf_leftover["neighbor"][neighbor_index] = None
    
    return {"neighbor": neighbor}

def set_timers(intf, intf_leftover):
    config = {}

    if "ip" in intf and "ospf" in intf["ip"] and "hello-interval" in intf["ip"]["ospf"]:
        config["hello-interval"] = intf["ip"]["ospf"]["hello-interval"]

        if "hello-interval" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["hello-interval"]
    if "ip" in intf and "ospf" in intf["ip"] and "retransmit-interval" in intf["ip"]["ospf"]:
        config["retransmission-interval"] = intf["ip"]["ospf"]["retransmit-interval"]

        if "retransmit-interval" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["retransmit-interval"]
    if ("ip" in intf and "ospf" in intf["ip"] and "dead-interval" in intf["ip"]["ospf"] 
        and "seconds" in intf["ip"]["ospf"]["dead-interval"]):
        config["dead-interval"] = intf["ip"]["ospf"]["dead-interval"]["seconds"]

        if "dead-interval" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["dead-interval"]
    
    return {"config": config}

def set_ospfv2_areas(ospfv2_area, area, area_key, ospf, ospf_leftover):
    area_by_id = get_area_by_id(ospfv2_area, area["id"])
    set_traffic_eng(area_by_id, ospf, ospf_leftover)
    set_virtual_links(area_by_id, area, area_key, ospf_leftover)
    set_stub(area_by_id, area, area_key, ospf_leftover)

def set_traffic_eng(area_by_id, ospf, ospf_leftover):
    is_enabled = False
    if "mpls" in ospf and "traffic-eng" in ospf["mpls"] and "area" in ospf["mpls"]["traffic-eng"]:
        for traffic_area_index, traffic_area_id in enumerate(ospf["mpls"]["traffic-eng"]["area"]):
            if area_by_id["identifier"] == traffic_area_id:
                is_enabled = True
                ospf_leftover["mpls"]["traffic-eng"]["area"][traffic_area_index] = None
                break

    area_by_id["mpls"] = {"config": {"traffic-engineering-enabled": is_enabled}}

def set_virtual_links(area_by_id, area, area_key, ospf_leftover):
    if "virtual-link" in area:
        for v_link_index, v_link in enumerate(area["virtual-link"]):
            if not "virtual-links" in area_by_id:
                area_by_id["virtual-links"] = {"virtual-link": []}
            if not "virtual-link" in area_by_id["virtual-links"]:
                area_by_id["virtual-links"]["virtual-link"] = []
            
            area_by_id["virtual-links"]["virtual-link"].append({
                "remote-router-id": v_link["id"],
                "config": {"remote-router-id": v_link["id"]}
            })
            ospf_leftover["area"][area_key]["virtual-link"][v_link_index] = None

def set_stub(area_by_id, area, area_key, ospf_leftover):
    # This might not be necessary, since configs are coming directly from NEDs.
    # stub_counter = 0
    
    # if "stub" in area:
    #     stub_counter += 1

    #     if "no-summary" in area["stub"]:
    #         stub_counter += 1
    # if "nssa" in area:
    #     stub_counter += 1
    
    # if stub_counter > 1:
    #     raise ValueError("NED OSPF config has more than one stub type")
    all_true = {
        "enabled": True,
        "default-information-originate": True
    }
    all_false = {
        "enabled": False,
        "default-information-originate": False
    }

    if "stub" in area:
        nssa_false = copy.deepcopy(all_false)
        nssa_false["no-summary"] = False

        if "no-summary" in area["stub"]:
            area_by_id["openconfig-ospfv2-ext:stub-options"] = {
                "totally-stubby": {"config": copy.deepcopy(all_true)},
                "stub": {"config": copy.deepcopy(all_false)},
                "nssa": {"config": nssa_false}
            }
        else:
            area_by_id["openconfig-ospfv2-ext:stub-options"] = {
                "totally-stubby": {"config": copy.deepcopy(all_false)},
                "stub": {"config": copy.deepcopy(all_true)},
                "nssa": {"config": nssa_false}
            }
        
        del ospf_leftover["area"][area_key]["stub"]
    elif "nssa" in area:
        nssa_true = copy.deepcopy(all_true)
        nssa_true["no-summary"] = "no-summary" in area["nssa"]
        area_by_id["openconfig-ospfv2-ext:stub-options"] = {
            "totally-stubby": {"config": copy.deepcopy(all_false)},
            "stub": {"config": copy.deepcopy(all_false)},
            "nssa": {"config": nssa_true}
        }
        del ospf_leftover["area"][area_key]["nssa"]
