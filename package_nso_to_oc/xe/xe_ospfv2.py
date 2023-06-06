#! /usr/bin/env python3
"""
This script is used by xe_network_instances.py to translate ospf configs from NED to OC.
"""

import copy
from functools import cmp_to_key
from importlib.util import find_spec

if (find_spec("package_nso_to_oc") is not None):
    from package_nso_to_oc.xe import common_xe
else:
    from xe import common_xe

ospf_network_types = {
    "broadcast": "BROADCAST_NETWORK",
    "point-to-point": "POINT_TO_POINT_NETWORK",
    "non-broadcast": "NON_BROADCAST_NETWORK"
}
xe_ospf_notes = []

def configure_xe_ospf(net_inst, vrf_interfaces, config_before, config_leftover, network_instances_notes):
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
            process_ospf(net_protocols, vrf_interfaces, config_leftover, ospf_index, ospf)

    network_instances_notes += xe_ospf_notes


def configure_xe_ospf_redistribution(net_inst, config_before, config_leftover, router_ospf_by_vrf):
    ospf_before = config_before.get("tailf-ned-cisco-ios:router", {"ospf": []}).get("ospf")

    if ospf_before == None or len(ospf_before) == 0:
        return
        
    instance_name = net_inst["openconfig-network-instance:name"]
    ospf_leftover = config_leftover.get("tailf-ned-cisco-ios:router", {"ospf": []}).get("ospf")

    for router_ospf_index in router_ospf_by_vrf.get(instance_name, []):
        router_ospf_before = ospf_before[router_ospf_index]
        router_ospf_leftover = ospf_leftover[router_ospf_index]
        redistribute = router_ospf_before.get("redistribute", {})
        redistribute_leftover = router_ospf_leftover.get("redistribute", {})

        if len(redistribute) == 0:
            continue

        common_xe.process_redistribute(net_inst, redistribute, redistribute_leftover, "OSPF", 
            router_ospf_before["id"])

        if "redistribute" in router_ospf_leftover and len(redistribute_leftover) == 0:
            del router_ospf_leftover["redistribute"]
        if "vrf" in router_ospf_leftover:
            del router_ospf_leftover["vrf"]
        if len(router_ospf_leftover) == 1 and "id" in router_ospf_leftover:
            del router_ospf_leftover["id"]


def get_interfaces_by_area(ospf_id, network_statements, vrf_interfaces):
    """
    Assigns OSPF enabled interfaces by area, based on OSPF network statements.
    Network statement wildcard masks are treated like ACLs to determine which interface will be attached
    to an OSPF area.
    Source: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/command/iro-cr-book/ospf-i1.html#wp2261032279

    TODO: Consider creating network statement sort algorithm
    As there can be multiple network statements, some may be more specific than others and they can point to different
    OSPF areas. The more specific statements should be prioritized over the less specific ones.
    """
    processed_interfaces = set()
    interfaces_by_area = {}
    sorted_network_statements = sorted(network_statements, key=cmp_to_key(sort_by_mask))
    unmatched_statements = set()
    matched_statements_with_intf = set()
    # This is for tracking only, because the same statement can appear again for unmatched statements.
    matched_statements = set()

    if len(sorted_network_statements) > 0:
        xe_ospf_notes.append("\n\nNo direct translation for network statements from XE to OC. \
Below are the leftover network statements.")
        xe_ospf_notes.append(f"OSPF ID: {ospf_id}")

    for net_stmt in sorted_network_statements:
        # Use get method for net_stmt, since it contains input values that we did not generate and cannot guarantee.
        stmt_mask = net_stmt.get("mask", "")
        area_id = net_stmt.get("area", "0")
        merged_statement_ip = binary_merge(net_stmt.get("ip", ""), net_stmt.get("mask", ""))

        for vrf_intf in vrf_interfaces:
            full_intf_name = vrf_intf["type"] + vrf_intf["name"]
            intf_addr = vrf_intf["ip"]["address"]["primary"]["address"]
            merged_vrf_intf_ip = binary_merge(intf_addr, stmt_mask)

            if merged_statement_ip == merged_vrf_intf_ip:
                matched_stmt = {
                    "interface": full_intf_name,
                    "interface_ip": intf_addr
                }
                matched_stmt.update(net_stmt)
                matched_statements.add(net_stmt_to_str(net_stmt))
                matched_statements_with_intf.add(net_stmt_to_str(matched_stmt))

                if (full_intf_name in processed_interfaces):
                    continue

                # If there's a match, then this interface is OSPF enabled
                processed_interfaces.add(full_intf_name)

                if not area_id in interfaces_by_area:
                    interfaces_by_area[area_id] = []

                interfaces_by_area[area_id].append(vrf_intf)
            else:
                unmatched_statements.add(net_stmt_to_str(net_stmt))

    if len(unmatched_statements) > 0 or len(matched_statements_with_intf) > 0:
        unmatched_statements -= matched_statements
        xe_ospf_notes.append("Matched statements:")
        for matched_statement in matched_statements_with_intf: xe_ospf_notes.append(matched_statement)
        xe_ospf_notes.append("Non-matching statements:")
        for unmatched_statement in unmatched_statements: xe_ospf_notes.append(unmatched_statement)
        xe_ospf_notes.append("\n")

    return interfaces_by_area


def net_stmt_to_str(net_stmt):
    net_stmt_str = ""
    
    if "interface" in net_stmt:
        net_stmt_str += f"\tInterface: {net_stmt['interface']}, Interface IP: {net_stmt['interface_ip']}\n"
    
    net_stmt_str += f"\tMask: {net_stmt.get('mask', '')}, IP: {net_stmt.get('ip', '')}, Area: {net_stmt.get('area', '')}"

    return net_stmt_str


def sort_by_mask(stmt1, stmt2):
    """
    A comparator to sort by mask, ordered from most specific (mask of 0.0.0.0) to least specific (mask of 255.255.255.255).
    """
    mask1 = stmt1.get("mask", None)
    mask2 = stmt2.get("mask", None)

    if not mask1 and not mask2:
        return 0
    if not mask1:
        return 1
    if not mask2:
        return -1

    mask1_octets = mask1.split(".")
    mask2_octets = mask2.split(".")

    # Sanity check
    if len(mask1_octets) != 4 or len(mask2_octets) != 4:
        raise ValueError("Invalid IP string provided")

    for octet_index in range(len(mask1_octets)):
        mask1_octet_int = int(mask1_octets[octet_index])
        mask2_octet_int = int(mask2_octets[octet_index])

        if mask1_octet_int == mask2_octet_int:
            continue

        return mask1_octet_int - mask2_octet_int

    return 0


def binary_merge(ip, mask):
    """
    Transform the IPs into binary string format and merge the binary strings via OR operation
    """
    merged_result = []
    ip_in_binary = get_binary_str(ip)
    mask_in_binary = get_binary_str(mask)

    for index in range(len(ip_in_binary)):
        ip_val = ip_in_binary[index] == "1"
        mask_val = mask_in_binary[index] == "1"
        merged_result.append("1" if ip_val or mask_val else "0")

    return "".join(merged_result)


def get_binary_str(ip_str):
    octets = ip_str.split(".")
    binary_octets = []

    for octet in octets:
        binary_octets.append(format(int(octet), "08b"))

    return "".join(binary_octets)


def get_ospfv2_global(net_protocols, prot_index):
    if (len(net_protocols) >= prot_index):
        if not "openconfig-network-instance:ospfv2" in net_protocols[prot_index]:
            net_protocols[prot_index]["openconfig-network-instance:ospfv2"] = {}
        if not "openconfig-network-instance:global" in net_protocols[prot_index]["openconfig-network-instance:ospfv2"]:
            net_protocols[prot_index]["openconfig-network-instance:ospfv2"]["openconfig-network-instance:global"] = {}

        return net_protocols[prot_index]["openconfig-network-instance:ospfv2"]["openconfig-network-instance:global"]
    else:
        # Sanity check, should not occur...
        raise IndexError(f"The protocol index {prot_index} does not exist.")


def get_ospfv2_area(net_protocols, prot_index):
    if (len(net_protocols) >= prot_index):
        if not "openconfig-network-instance:ospfv2" in net_protocols[prot_index]:
            net_protocols[prot_index]["openconfig-network-instance:ospfv2"] = {}
        if not "areas" in net_protocols[prot_index]["openconfig-network-instance:ospfv2"]:
            net_protocols[prot_index]["openconfig-network-instance:ospfv2"]["openconfig-network-instance:areas"] = {
                "openconfig-network-instance:area": []}

        return net_protocols[prot_index]["openconfig-network-instance:ospfv2"]["openconfig-network-instance:areas"][
            "openconfig-network-instance:area"]
    else:
        # Sanity check, should not occur...
        raise IndexError(f"The protocol index {prot_index} does not exist.")


def get_area_by_id(ospfv2_area, area_id):
    for area in ospfv2_area:
        if area["openconfig-network-instance:identifier"] == area_id:
            return area

    new_area = {"openconfig-network-instance:identifier": area_id,
                "openconfig-network-instance:config": {"openconfig-network-instance:identifier": area_id}}
    ospfv2_area.append(new_area)

    return new_area


def is_area_present_by_id(ospfv2_area, id):
    for area in ospfv2_area:
        if area.get("openconfig-network-instance:identifier", None) == id:
            return True

    return False


def get_intf_by_intf_number(intf_attr, intf_number):
    for intf in intf_attr:
        if str(intf["name"]) == intf_number:
            return intf


def process_ospf(net_protocols, vrf_interfaces, config_leftover, ospf_index, ospf):
    ospf_leftover = config_leftover.get("tailf-ned-cisco-ios:router", {}).get("ospf")[ospf_index]
    # If we got here, we init an empty dict and append to protocol list for future use.
    net_protocols.append({})
    prot_index = len(net_protocols) - 1
    set_network_config(ospf_leftover, net_protocols, prot_index, ospf)
    set_ospf2_global_config(ospf_leftover, net_protocols, prot_index, ospf)
    set_graceful_restart_ietf(ospf_leftover, net_protocols, prot_index, ospf)
    set_vrf_lite(ospf_leftover, net_protocols, prot_index, ospf)
    set_default_info_originate(ospf_leftover, net_protocols, prot_index, ospf)
    check_areas(ospf_leftover, net_protocols, vrf_interfaces, config_leftover, prot_index, ospf)
    set_mpls_ldp_sync(ospf_leftover, net_protocols, prot_index, ospf)
    set_timers_lsa(ospf_leftover, net_protocols, prot_index, ospf)
    set_timers_spf(ospf_leftover, net_protocols, prot_index, ospf)
    set_auto_cost_ref_bandwidth(ospf_leftover, net_protocols, prot_index, ospf)


def set_network_config(ospf_leftover, net_protocols, prot_index, ospf):
    net_protocols[prot_index]["openconfig-network-instance:identifier"] = "OSPF"
    net_protocols[prot_index]["openconfig-network-instance:name"] = f'{ospf.get("id")}'
    temp_ospf = {"openconfig-network-instance:config": {
        "openconfig-network-instance:identifier": "OSPF",
        "openconfig-network-instance:name": f'{ospf.get("id")}',
        "openconfig-network-instance:enabled": True
    }}
    net_protocols[prot_index].update(temp_ospf)

    # Don't remove keys until everything is in OC
    # if ospf_leftover.get("id"):
    #     del ospf_leftover["id"]


def set_ospf2_global_config(ospf_leftover, net_protocols, prot_index, ospf):
    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)

    if (not ospf.get("router-id") and not ospf.get("log-adjacency-changes")
            and not ospf.get("compatible") and not ospf.get("prefix-suppression")):
        ospfv2_global["config"] = {
            "openconfig-network-instance:log-adjacency-changes": False,
            "openconfig-network-instance:summary-route-cost-mode": "RFC1583_COMPATIBLE",
            "openconfig-network-instance:hide-transit-only-networks": False
        }

        return

    ospfv2_global_config = {}

    if ospf.get("router-id"):
        ospfv2_global_config["openconfig-network-instance:router-id"] = f'{ospf.get("router-id")}'
        del ospf_leftover["router-id"]
    if ospf.get("log-adjacency-changes"):
        ospfv2_global_config["openconfig-network-instance:log-adjacency-changes"] = True
    else:
        ospfv2_global_config["openconfig-network-instance:log-adjacency-changes"] = False
    if ospf.get("compatible") and ospf["compatible"].get("rfc1583") is False:
        ospfv2_global_config["openconfig-network-instance:summary-route-cost-mode"] = "RFC2328_COMPATIBLE"
    else:
        ospfv2_global_config["openconfig-network-instance:summary-route-cost-mode"] = "RFC1583_COMPATIBLE"
    if ospf.get("prefix-suppression"):
        ospfv2_global_config["openconfig-network-instance:hide-transit-only-networks"] = True
    else:
        ospfv2_global_config["openconfig-network-instance:hide-transit-only-networks"] = False

    # Common clean up
    if "log-adjacency-changes" in ospf_leftover:
        del ospf_leftover["log-adjacency-changes"]
    if "compatible" in ospf_leftover:
        del ospf_leftover["compatible"]
    if "prefix-suppression" in ospf_leftover:
        del ospf_leftover["prefix-suppression"]

    ospfv2_global["openconfig-network-instance:config"] = ospfv2_global_config


def set_graceful_restart_ietf(ospf_leftover, net_protocols, prot_index, ospf):
    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
    graceful_restart_config = {
        "openconfig-network-instance:graceful-restart": {"openconfig-network-instance:config": {}}}

    if ospf.get("nsf-ietf") and ospf["nsf-ietf"].get("nsf") and "ietf" in ospf["nsf-ietf"]["nsf"]:
        graceful_restart_config["openconfig-network-instance:graceful-restart"]["openconfig-network-instance:config"][
            "openconfig-network-instance:enabled"] = True
        del ospf_leftover["nsf-ietf"]["nsf"]["ietf"]
    else:
        graceful_restart_config["openconfig-network-instance:graceful-restart"]["openconfig-network-instance:config"][
            "openconfig-network-instance:enabled"] = False

    ospfv2_global.update(graceful_restart_config)


def set_vrf_lite(ospf_leftover, net_protocols, prot_index, ospf):
    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)

    if not ospfv2_global.get("openconfig-network-instance:config"):
        ospfv2_global["openconfig-network-instance:config"] = {}

    if ospf.get("capability") and "vrf-lite" in ospf["capability"]:
        ospfv2_global["openconfig-network-instance:config"]["openconfig-ospfv2-ext:capability-vrf-lite"] = True
        del ospf_leftover["capability"]
    else:
        ospfv2_global["openconfig-network-instance:config"]["openconfig-ospfv2-ext:capability-vrf-lite"] = False


def set_default_info_originate(ospf_leftover, net_protocols, prot_index, ospf):
    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)

    if not "default-information" in ospf or not "originate" in ospf["default-information"]:
        ospfv2_global["openconfig-network-instance:config"].update({
                                                                       "openconfig-ospfv2-ext:default-information-originate": {
                                                                           "openconfig-ospfv2-ext:config": {
                                                                               "openconfig-ospfv2-ext:enabled": False}}})
        return

    if not "openconfig-network-instance:config" in ospfv2_global:
        ospfv2_global["openconfig-network-instance:config"] = {}

    oc_default_info_originate = {"openconfig-ospfv2-ext:default-information-originate": {
        "openconfig-ospfv2-ext:config": {"openconfig-ospfv2-ext:enabled": True}}}
    originate_config = oc_default_info_originate["openconfig-ospfv2-ext:default-information-originate"][
        "openconfig-ospfv2-ext:config"]
    default_info_originate = ospf["default-information"]["originate"]

    if "always" in default_info_originate:
        originate_config["openconfig-ospfv2-ext:always"] = True

        if "always" in ospf_leftover["default-information"]["originate"]:
            del ospf_leftover["default-information"]["originate"]["always"]
    if "metric" in default_info_originate:
        originate_config["openconfig-ospfv2-ext:metric"] = default_info_originate["metric"]

        if "metric" in ospf_leftover["default-information"]["originate"]:
            del ospf_leftover["default-information"]["originate"]["metric"]
    if "metric-type" in default_info_originate:
        originate_config["openconfig-ospfv2-ext:metric-type"] = default_info_originate["metric-type"]

        if "metric-type" in ospf_leftover["default-information"]["originate"]:
            del ospf_leftover["default-information"]["originate"]["metric-type"]
    # TODO add route-maps to OC Services
    # if "route-map" in default_info_originate:
    #     originate_config["route-map"] = default_info_originate["route-map"]
    #
    #     if "route-map" in ospf_leftover["default-information"]["originate"]:
    #         del ospf_leftover["default-information"]["originate"]["route-map"]

    ospfv2_global["openconfig-network-instance:config"].update(oc_default_info_originate)


def check_areas(ospf_leftover, net_protocols, vrf_interfaces, config_leftover, prot_index, ospf):
    intf_config_leftover = config_leftover.get("tailf-ned-cisco-ios:interface", {})
    ospfv2_area = get_ospfv2_area(net_protocols, prot_index)
    interfaces_by_area = get_interfaces_by_area(ospf.get("id"), ospf.get("network", []), vrf_interfaces)
    area_list = populate_area_list(ospf)
    is_area_0_present = check_for_area_0(area_list)
    for area in area_list:
        leftover_area = list(filter(lambda temp_area: temp_area["id"] == area["id"], ospf_leftover.get("area", [])))
        set_ospfv2_areas(ospfv2_area, area, leftover_area, ospf, ospf_leftover)

        if is_area_0_present and int(area["id"]) != 0:
            # We do this as long as area 0 is available and destination area is not 0.
            set_inter_area_propagation_policy(net_protocols, prot_index, area, leftover_area)

        for current_intf in interfaces_by_area.get(area.get("id", 0), []):
            intf_type, intf_number = (current_intf["type"], current_intf["name"])
            intf_name = intf_type + intf_number
            if (intf_type == "Port-channel" or intf_type == "LISP") and "." in str(intf_number):
                intf_attr_leftover = intf_config_leftover.get(f"{intf_type}-subinterface", {}).get(intf_type, {})
            else:
                intf_attr_leftover = intf_config_leftover.get(intf_type, {})
            intf_leftover = get_intf_by_intf_number(intf_attr_leftover, intf_number)
            set_ospfv2_intf_areas(ospfv2_area, intf_leftover, area, intf_name, current_intf, ospf, ospf_leftover)


def populate_area_list(ospf):
    area_list = []
    area_id_set = set()

    # Populate with existing areas defined by NED first, if any.
    for area in ospf.get("area", []):
        area_list.append(area)
        area_id_set.add(area["id"])

    # Populate with area based on OSPF network statement, if area wasn't already defined by the NED
    for net_stmt in ospf.get("network", []):
        # Is adding a default necessary, or should we always expect a network statement to contain an area ID?
        area_id = net_stmt.get("area", "0")

        if area_id in area_id_set:
            continue
        else:
            area_id_set.add(area_id)

        area_list.append({"id": area_id})
    return area_list


def check_for_area_0(area_list):
    for area in area_list:
        if area["id"] == 0:
            return True

    return False


def set_inter_area_propagation_policy(net_protocols, prot_index, area, leftover_area):
    if "id" in area and "filter-list" in area and len(area["filter-list"]) == 1:
        ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
        import_policy_prefix = area["filter-list"][0]["prefix"]
        service_policy = {}

        if not "openconfig-network-instance:inter-area-propagation-policies" in ospfv2_global:
            ospfv2_global["openconfig-network-instance:inter-area-propagation-policies"] = {}
        if not "openconfig-network-instance:inter-area-propagation-policy" in ospfv2_global[
            "openconfig-network-instance:inter-area-propagation-policies"]:
            ospfv2_global["openconfig-network-instance:inter-area-propagation-policies"][
                "openconfig-network-instance:inter-area-propagation-policy"] = []

        # Per Steven Mosher, 0 is the implied source area
        service_policy["openconfig-network-instance:src-area"] = 0
        service_policy["openconfig-network-instance:dst-area"] = area["id"]
        service_policy["openconfig-network-instance:config"] = {
            "openconfig-network-instance:src-area": 0,
            "openconfig-network-instance:dst-area": area["id"],
            "openconfig-network-instance:import-policy": [import_policy_prefix]
        }

        ospfv2_global["openconfig-network-instance:inter-area-propagation-policies"][
            "openconfig-network-instance:inter-area-propagation-policy"].append(service_policy)

        if len(leftover_area) > 0 and "filter-list" in leftover_area[0]:
            del leftover_area[0]["filter-list"]


def set_mpls_ldp_sync(ospf_leftover, net_protocols, prot_index, ospf):
    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
    is_igp_ldp_sync = "mpls" in ospf and "ldp" in ospf["mpls"] and "sync" in ospf["mpls"]["ldp"]
    ospfv2_global["openconfig-network-instance:mpls"] = {"openconfig-network-instance:igp-ldp-sync": {
        "openconfig-network-instance:config": {"openconfig-network-instance:enabled": is_igp_ldp_sync}}}

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
            config["openconfig-network-instance:initial-delay"] = lsa["start-interval"]
            config["openconfig-network-instance:maximum-delay"] = lsa["max-interval"]
            config["openconfig-ospfv2-ext:hold-time"] = lsa["hold-interval"]

            if not "openconfig-network-instance:timers" in ospfv2_global:
                ospfv2_global["openconfig-network-instance:timers"] = {}
            if not "openconfig-network-instance:lsa-generation" in ospfv2_global["openconfig-network-instance:timers"]:
                ospfv2_global["openconfig-network-instance:timers"]["openconfig-network-instance:lsa-generation"] = {}

            ospfv2_global["openconfig-network-instance:timers"]["openconfig-network-instance:lsa-generation"].update(
                {"openconfig-network-instance:config": config})
        else:
            raise ValueError(
                "XE OSPF throttle timers lsa needs values for start-interval, hold-interval, and max-interval")

    del ospf_leftover["timers"]["throttle"]["lsa"]


def set_timers_spf(ospf_leftover, net_protocols, prot_index, ospf):
    if not "timers" in ospf or not "throttle" in ospf["timers"] or not "spf" in ospf["timers"]["throttle"]:
        return

    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
    config = {}
    spf = ospf["timers"]["throttle"]["spf"]

    if "spf-start" in spf or "spf-hold" in spf or "spf-max-wait" in spf:
        if "spf-start" in spf and "spf-hold" in spf and "spf-max-wait" in spf:
            config["openconfig-network-instance:initial-delay"] = spf["spf-start"]
            config["openconfig-network-instance:maximum-delay"] = spf["spf-max-wait"]
            config["openconfig-ospfv2-ext:hold-time"] = spf["spf-hold"]

            if not "openconfig-network-instance:timers" in ospfv2_global:
                ospfv2_global["openconfig-network-instance:timers"] = {}
            if not "openconfig-network-instance:spf" in ospfv2_global["openconfig-network-instance:timers"]:
                ospfv2_global["openconfig-network-instance:timers"]["openconfig-network-instance:spf"] = {}

            ospfv2_global["openconfig-network-instance:timers"]["openconfig-network-instance:spf"].update(
                {"openconfig-network-instance:config": config})
        else:
            raise ValueError("XE OSPF throttle timers spf needs values for spf-start, spf-hold, and spf-max-wait")

    del ospf_leftover["timers"]["throttle"]["spf"]


def set_auto_cost_ref_bandwidth(ospf_leftover, net_protocols, prot_index, ospf):
    # if not "auto-cost reference-bandwidth" in ospf:
    if not "auto-cost" in ospf or not "reference-bandwidth" in ospf["auto-cost"]:
        return

    ospfv2_global = get_ospfv2_global(net_protocols, prot_index)
    auto_cost = ospf["auto-cost"]

    ospfv2_global["openconfig-network-instance:config"].update(
        {"openconfig-ospfv2-ext:auto-cost-ref-bandwidth": auto_cost["reference-bandwidth"]})

    del ospf_leftover["auto-cost"]["reference-bandwidth"]


def set_ospfv2_intf_areas(ospfv2_area, intf_leftover, area, intf_name, intf, ospf, ospf_leftover):
    intf_config = {"openconfig-network-instance:id": intf_name}
    set_network_type(intf, intf_leftover, intf_config)
    set_metric(intf, intf_leftover, intf_config)
    set_passive(ospf, ospf_leftover, intf_config, intf_name)
    set_priority(intf, intf_leftover, intf_config)
    area_intf = get_area_by_id(ospfv2_area, area["id"])

    if not "openconfig-network-instance:interfaces" in area_intf:
        area_intf["openconfig-network-instance:interfaces"] = {"openconfig-network-instance:interface": []}
    if not "openconfig-network-instance:interface" in area_intf["openconfig-network-instance:interfaces"]:
        area_intf["openconfig-network-instance:interfaces"]["openconfig-network-instance:interface"] = []

    area_intf["openconfig-network-instance:interfaces"]["openconfig-network-instance:interface"].append({
        "openconfig-network-instance:id": intf_name,
        "openconfig-network-instance:config": intf_config,
        "openconfig-network-instance:enable-bfd": {"openconfig-network-instance:config": {
            "openconfig-network-instance:enabled": is_bfd_enabled(intf, intf_leftover)}},
        "openconfig-network-instance:neighbors": set_neighbors(ospf, ospf_leftover),
        "openconfig-network-instance:timers": set_timers(intf, intf_leftover),
        "openconfig-ospfv2-ext:authentication": set_authentication(intf, intf_leftover),
    })


def set_network_type(intf, intf_leftover, intf_config):
    if ("ip" in intf and "ospf" in intf["ip"] and "network" in intf["ip"]["ospf"] and len(
            intf["ip"]["ospf"]["network"]) > 0
            and intf["ip"]["ospf"]["network"][0] in ospf_network_types):
        intf_config["openconfig-network-instance:network-type"] = ospf_network_types[intf["ip"]["ospf"]["network"][0]]

        if "network" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["network"]


def set_metric(intf, intf_leftover, intf_config):
    if "ip" in intf and "ospf" in intf["ip"] and "cost" in intf["ip"]["ospf"]:
        intf_config["openconfig-network-instance:metric"] = intf["ip"]["ospf"]["cost"]

        if "cost" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["cost"]


def set_passive(ospf, ospf_leftover, intf_config, intf_name):
    if "passive-interface" in ospf and "interface" in ospf["passive-interface"]:
        # We're brute forcing, but we don't expect 100s of interfaces anyway...
        for passive_intf in ospf["passive-interface"]["interface"]:
            if passive_intf["name"] == intf_name:
                intf_config["openconfig-network-instance:passive"] = True
                break
        else:
            intf_config["passive"] = False

    if ("passive-interface" in ospf_leftover):
        del ospf_leftover["passive-interface"]


def set_priority(intf, intf_leftover, intf_config):
    if "ip" in intf and "ospf" in intf["ip"] and "priority" in intf["ip"]["ospf"]:
        intf_config["openconfig-network-instance:priority"] = intf["ip"]["ospf"]["priority"]

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

            if "cost-database-filter-container" in ospf_neighbor and "cost" in ospf_neighbor[
                "cost-database-filter-container"]:
                metric = ospf_neighbor["cost-database-filter-container"]["cost"]

            neighbor.append({
                "openconfig-network-instance:router-id": ospf_neighbor.get("ip", ""),
                "openconfig-network-instance:config": {
                    "openconfig-network-instance:router-id": ospf_neighbor.get("ip", ""),
                    "openconfig-network-instance:metric": metric
                }
            })

            # Deleting indexes while iterating causes issues, just blank out or nullify
            ospf_leftover["neighbor"][neighbor_index] = None

    return {"neighbor": neighbor}


def set_timers(intf, intf_leftover):
    config = {}

    if "ip" in intf and "ospf" in intf["ip"] and "hello-interval" in intf["ip"]["ospf"]:
        config["openconfig-network-instance:hello-interval"] = intf["ip"]["ospf"]["hello-interval"]

        if "hello-interval" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["hello-interval"]
    if "ip" in intf and "ospf" in intf["ip"] and "retransmit-interval" in intf["ip"]["ospf"]:
        config["openconfig-network-instance:retransmission-interval"] = intf["ip"]["ospf"]["retransmit-interval"]

        if "retransmit-interval" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["retransmit-interval"]
    if ("ip" in intf and "ospf" in intf["ip"] and "dead-interval" in intf["ip"]["ospf"]
            and "seconds" in intf["ip"]["ospf"]["dead-interval"]):
        config["openconfig-network-instance:dead-interval"] = intf["ip"]["ospf"]["dead-interval"]["seconds"]

        if "dead-interval" in intf_leftover["ip"]["ospf"]:
            del intf_leftover["ip"]["ospf"]["dead-interval"]

    return {"openconfig-network-instance:config": config}


def set_authentication(intf, intf_leftover):
    # Authentication type: unconfigured, null, simple and md5
    authentication = {"openconfig-ospfv2-ext:config": []}
    auth_list = authentication["openconfig-ospfv2-ext:config"]
    is_auth_enabled = type(intf.get("ip", {}).get("ospf", {}).get("authentication", '')) is dict
    is_mess_digest = "ip" in intf and "ospf" in intf["ip"] and "message-digest-key" in intf["ip"]["ospf"]
    if not is_auth_enabled:
        # Unconfigured
        config = {
            "openconfig-ospfv2-ext:authentication-type": 'UNCONFIGURED'
        }
        auth_list.append(config)
    elif is_auth_enabled and len(intf["ip"]["ospf"]["authentication"]) == 0:
        # Simple
        config = {
            "openconfig-ospfv2-ext:authentication-type": "SIMPLE",
        }
        del intf_leftover["ip"]["ospf"]["authentication"]
        if intf.get("ip", {}).get("ospf", {}).get("authentication-key", {}).get("secret", ""):
            config["openconfig-ospfv2-ext:simple-password"] = intf.get("ip", {}).get("ospf", {}).get(
                "authentication-key", {}).get("secret", "")
            intf["ip"]["ospf"]["authentication-key"]["secret"] = None
        auth_list.append(config)
    else:
        updated_ospf_auth_list = []

        for index, auth in enumerate(intf["ip"]["ospf"]["authentication"]):
            # NULL
            if "null" in intf["ip"]["ospf"]["authentication"]:
                config = {
                    "openconfig-ospfv2-ext:authentication-type": 'NULL'
                }
                intf_leftover["ip"]["ospf"]["authentication"][index] = None
                auth_list.append(config)
            # Key-chain
            if "key-chain" in intf["ip"]["ospf"]["authentication"]:
                config = {
                    "openconfig-ospfv2-ext:authentication-type": 'KEY-CHAIN'
                }
                if intf.get("ip", {}).get("ospf", {}).get("authentication", {}).get("key-chain", ""):
                    config["openconfig-ospfv2-ext:key-chain"] = intf.get("ip", {}).get("ospf", {}).get("authentication", {}).get("key-chain", "")
                intf_leftover["ip"]["ospf"]["authentication"][index] = None
                auth_list.append(config)
            # MD5
            if "message-digest" in intf["ip"]["ospf"]["authentication"]:
                config = {
                    "openconfig-ospfv2-ext:authentication-type": 'MD5'
                }
                intf_leftover["ip"]["ospf"]["authentication"][index] = None
                auth_list.append(config)
            if intf_leftover["ip"]["ospf"]["authentication"][index]:
                updated_ospf_auth_list.append(intf_leftover["ip"]["ospf"]["authentication"][index])

        if len(updated_ospf_auth_list) > 0:
            intf_leftover["ip"]["ospf"]["authentication"] = updated_ospf_auth_list
        else:
            del intf_leftover["ip"]["ospf"]["authentication"]

    if is_mess_digest:
        authentication.update(set_message_digest(intf, intf_leftover))

    return authentication


def set_message_digest(intf, intf_leftover):
    # Configure md5 keys
    mess_digest = {"openconfig-ospfv2-ext:md5-authentication-keys": {
        "openconfig-ospfv2-ext:md5-authentication-key": []
    }}
    mess_digest_list = mess_digest["openconfig-ospfv2-ext:md5-authentication-keys"][
        "openconfig-ospfv2-ext:md5-authentication-key"]
    updated_md_key_list = []

    for index, message_digest in enumerate(intf["ip"]["ospf"]["message-digest-key"]):
        config = {
            "openconfig-ospfv2-ext:key-id": message_digest["id"],
            "openconfig-ospfv2-ext:config": {
                "openconfig-ospfv2-ext:key-id": message_digest["id"],
                "openconfig-ospfv2-ext:key": message_digest["md5"]["secret"]
            }
        }
        mess_digest_list.append(config)

        if "message-digest-key" in intf_leftover["ip"]["ospf"]:
            intf_leftover["ip"]["ospf"]["message-digest-key"][index] = None

    for md_key in intf_leftover.get("ip", {}).get("ospf", {}).get("message-digest-key", []):
        if md_key:
            updated_md_key_list.append(md_key)

    if len(updated_md_key_list) > 0:
        intf_leftover["ip"]["ospf"]["message-digest-key"] = updated_md_key_list
    elif "message-digest-key" in intf_leftover["ip"]["ospf"]:
        del intf_leftover["ip"]["ospf"]["message-digest-key"]

    return mess_digest


def set_ospfv2_areas(ospfv2_area, area, leftover_area, ospf, ospf_leftover):
    area_by_id = get_area_by_id(ospfv2_area, area["id"])
    set_traffic_eng(area_by_id, ospf, ospf_leftover)
    set_virtual_links(area_by_id, area, leftover_area)
    set_stub(area_by_id, area, leftover_area)


def set_traffic_eng(area_by_id, ospf, ospf_leftover):
    is_enabled = False
    if "mpls" in ospf and "traffic-eng" in ospf["mpls"] and "area" in ospf["mpls"]["traffic-eng"]:
        for traffic_area_index, traffic_area_id in enumerate(ospf["mpls"]["traffic-eng"]["area"]):
            if area_by_id["openconfig-network-instance:identifier"] == traffic_area_id:
                is_enabled = True
                ospf_leftover["mpls"]["traffic-eng"]["area"][traffic_area_index] = None
                break

    area_by_id["openconfig-network-instance:mpls"] = {
        "openconfig-network-instance:config": {"openconfig-network-instance:traffic-engineering-enabled": is_enabled}}


def set_virtual_links(area_by_id, area, leftover_area):
    if "virtual-link" in area:
        for v_link_index, v_link in enumerate(area["virtual-link"]):
            if not "openconfig-network-instance:virtual-links" in area_by_id:
                area_by_id["openconfig-network-instance:virtual-links"] = {
                    "openconfig-network-instance:virtual-link": []}
            if not "openconfig-network-instance:virtual-link" in area_by_id[
                "openconfig-network-instance:virtual-links"]:
                area_by_id["openconfig-network-instance:virtual-links"]["openconfig-network-instance:virtual-link"] = []

            area_by_id["openconfig-network-instance:virtual-links"]["openconfig-network-instance:virtual-link"].append({
                "openconfig-network-instance:remote-router-id": v_link["id"],
                "openconfig-network-instance:config": {"openconfig-network-instance:remote-router-id": v_link["id"]}
            })

            if len(leftover_area) > 0 and "virtual-link" in leftover_area[0]:
                leftover_area[0]["virtual-link"][v_link_index] = None


def set_stub(area_by_id, area, leftover_area):
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
        "openconfig-ospfv2-ext:enabled": True,
        "openconfig-ospfv2-ext:default-information-originate": True
    }
    all_false = {
        "openconfig-ospfv2-ext:enabled": False,
        "openconfig-ospfv2-ext:default-information-originate": False
    }

    if "stub" in area:
        nssa_false = copy.deepcopy(all_false)
        nssa_false["openconfig-ospfv2-ext:no-summary"] = False

        if "no-summary" in area["stub"]:
            area_by_id["openconfig-ospfv2-ext:stub-options"] = {
                "openconfig-ospfv2-ext:totally-stubby": {"openconfig-ospfv2-ext:config": copy.deepcopy(all_true)},
                "openconfig-ospfv2-ext:stub": {"openconfig-ospfv2-ext:config": copy.deepcopy(all_false)},
                "openconfig-ospfv2-ext:nssa": {"openconfig-ospfv2-ext:config": nssa_false}
            }
        else:
            area_by_id["openconfig-ospfv2-ext:stub-options"] = {
                "openconfig-ospfv2-ext:totally-stubby": {"openconfig-ospfv2-ext:config": copy.deepcopy(all_false)},
                "openconfig-ospfv2-ext:stub": {"openconfig-ospfv2-ext:config": copy.deepcopy(all_true)},
                "openconfig-ospfv2-ext:nssa": {"openconfig-ospfv2-ext:config": nssa_false}
            }

        if len(leftover_area) > 0 and "stub" in leftover_area[0]:
            del leftover_area[0]["stub"]
    elif "nssa" in area:
        nssa_true = copy.deepcopy(all_true)
        nssa_true["openconfig-ospfv2-ext:no-summary"] = "no-summary" in area["nssa"]
        area_by_id["openconfig-ospfv2-ext:stub-options"] = {
            "openconfig-ospfv2-ext:totally-stubby": {"openconfig-ospfv2-ext:config": copy.deepcopy(all_false)},
            "openconfig-ospfv2-ext:stub": {"openconfig-ospfv2-ext:config": copy.deepcopy(all_false)},
            "openconfig-ospfv2-ext:nssa": {"openconfig-ospfv2-ext:config": nssa_true}
        }

        if len(leftover_area) > 0 and "nssa" in leftover_area[0]:
            del leftover_area[0]["nssa"]
