#! /usr/bin/env python3
"""
This script is used by xe_network_instances.py to translate BGP configs from NED to OC.
"""

import copy
from importlib.util import find_spec

if (find_spec("package_nso_to_oc") is not None):
    from package_nso_to_oc import common
    from package_nso_to_oc.xe import common_xe
else:
    import common
    from xe import common_xe

ospf_network_types = {
    "broadcast": "BROADCAST_NETWORK",
    "point-to-point": "POINT_TO_POINT_NETWORK",
    "non-broadcast": "NON_BROADCAST_NETWORK"
}
redistribute_type = {
    "ospf": "OSPF",
    "static": "STATIC",
    "connected": "DIRECTLY_CONNECTED"
}
xe_bgp_notes = []
ATTR_PEER = "peer-group-name"
ATTR_NEIGHBOR = "neighbor-address"

neighbors = {}
peers = {}

def configure_xe_bgp(net_inst, config_before, config_leftover, network_instances_notes):
    neighbors.clear()
    peers.clear()
    bgp_before = config_before.get("tailf-ned-cisco-ios:router", {"bgp": []}).get("bgp")

    if bgp_before == None or len(bgp_before) == 0:
        return

    instance_name = net_inst["openconfig-network-instance:name"]
    net_protocols = net_inst["openconfig-network-instance:protocols"]["openconfig-network-instance:protocol"]
    bgp_protocol = get_bgp_protocol(net_protocols)
    bgp_leftover = config_leftover.get("tailf-ned-cisco-ios:router", {"bgp": []}).get("bgp")
    bgp_protocol_bgp = bgp_protocol["openconfig-network-instance:bgp"]

    bgp_protocol["openconfig-network-instance:config"]["openconfig-network-instance:enabled"] = True
    bgp_protocol_bgp["openconfig-network-instance:global"] = {
        "openconfig-network-instance:config": {
            "openconfig-network-instance:as": bgp_before[0].get("as-no")
        }
    }
    oc_bgp_global = bgp_protocol_bgp["openconfig-network-instance:global"]

    # remaining will need asn
    # if bgp_leftover[0].get("as-no") != None:
    #     del bgp_leftover[0]["as-no"]

    if instance_name == "default":
        process_bgp_global(oc_bgp_global, bgp_before[0], bgp_leftover[0])
        process_neighbor_and_neighbor_tag(False, ATTR_PEER, bgp_before[0], bgp_leftover[0])
        process_neighbor_and_neighbor_tag(False, ATTR_NEIGHBOR, bgp_before[0], bgp_leftover[0])

    # if bgp_before[0].get("bgp", {}).get("default", {}).get("ipv4-unicast", True) == False:
    oc_bgp_global["openconfig-network-instance:afi-safis"] = {"openconfig-network-instance:afi-safi": []}
    oc_bgp_afi = oc_bgp_global["openconfig-network-instance:afi-safis"]["openconfig-network-instance:afi-safi"]
    
    if instance_name == "default":
        process_address_family_default(bgp_protocol_bgp, oc_bgp_afi, bgp_before[0], bgp_leftover[0])
    else:
        process_address_family_vrf(instance_name, bgp_protocol_bgp, oc_bgp_afi, bgp_before[0], bgp_leftover[0])

    if bgp_leftover[0].get("bgp", {}).get("default", {}).get("ipv4-unicast") != None:
        del bgp_leftover[0]["bgp"]["default"]["ipv4-unicast"]
    if bgp_leftover[0].get("bgp", {}).get("default") != None and len(bgp_leftover[0]["bgp"]["default"]) == 0:
        del bgp_leftover[0]["bgp"]["default"]

    if len(oc_bgp_afi) == 0:
        del oc_bgp_global["openconfig-network-instance:afi-safis"]
    if len(peers.values()) == 0:
        del bgp_protocol_bgp["openconfig-network-instance:peer-groups"]
    else:
        bgp_protocol_bgp["openconfig-network-instance:peer-groups"][
            "openconfig-network-instance:peer-group"] = list(peers.values())
    if len(neighbors.values()) == 0:
        del bgp_protocol_bgp["openconfig-network-instance:neighbors"]
    else:
        bgp_protocol_bgp["openconfig-network-instance:neighbors"][
            "openconfig-network-instance:neighbor"] = list(neighbors.values())
    
    network_instances_notes += xe_bgp_notes

def configure_xe_bgp_redistribution(net_inst, config_before, config_leftover):
    bgp_before = config_before.get("tailf-ned-cisco-ios:router", {"bgp": []}).get("bgp")

    if bgp_before == None or len(bgp_before) == 0:
        return
        
    instance_name = net_inst["openconfig-network-instance:name"]
    bgp_protocol = get_bgp_protocol(net_inst["openconfig-network-instance:protocols"][
        "openconfig-network-instance:protocol"])
    afi = (bgp_protocol.get("openconfig-network-instance:bgp", {}).get("openconfig-network-instance:global", {})
        .get("openconfig-network-instance:afi-safis", {}).get("openconfig-network-instance:afi-safi", []))
    bgp_leftover = config_leftover.get("tailf-ned-cisco-ios:router", {"bgp": []}).get("bgp")
    redistribute = None
    redistribute_leftover = {}
    vrf_index = None
    ipv4_index = None
    
    if len(afi) > 0:
        if "with-vrf" in bgp_leftover[0]["address-family"] and instance_name != "default":
            (redistribute, ipv4_index, vrf_index) = get_vrf_redistribute(instance_name, bgp_before[0])
        else:
            (redistribute, ipv4_index) = get_global_redistribute(bgp_before[0])

    if vrf_index is None and ipv4_index != None:
        if len(afi) > 0:
            if (len(bgp_leftover[0].get("address-family", {}).get("ipv4", [])) > 0
                and bgp_leftover[0]["address-family"]["ipv4"][ipv4_index]):
                redistribute_leftover = bgp_leftover[0]["address-family"]["ipv4"][ipv4_index].get("redistribute")
            else:
                redistribute_leftover = {}
    elif vrf_index != None and ipv4_index != None:
        if len(afi) > 0:
            if len(bgp_leftover[0].get("address-family", {}).get("with-vrf", {}).get("ipv4", [])) > ipv4_index:
                ipv4_vrf = bgp_leftover[0]["address-family"]["with-vrf"]["ipv4"][ipv4_index]

                if len(ipv4_vrf.get("vrf", [])) > vrf_index:
                    redistribute_leftover = bgp_leftover[0]["address-family"]["with-vrf"]["ipv4"][ipv4_index][
                        "vrf"][vrf_index].get("redistribute")
                else:
                    redistribute_leftover = {}
            else:
                redistribute_leftover = {}

    common_xe.process_redistribute(net_inst, redistribute, redistribute_leftover, "BGP")

    if vrf_index is None and ipv4_index != None:
        if (len(afi) > 0 and redistribute_leftover != None and len(redistribute_leftover) == 0
            and bgp_leftover[0]["address-family"]["ipv4"][ipv4_index]):
            
            del bgp_leftover[0]["address-family"]["ipv4"][ipv4_index]["redistribute"]
        elif (redistribute_leftover != None and len(redistribute_leftover) == 0
            and bgp_leftover[0].get("redistribute")):
            
            del bgp_leftover[0]["redistribute"]
    elif vrf_index != None and ipv4_index != None:
        if (len(afi) > 0 and redistribute_leftover != None and len(redistribute_leftover) == 0
            and bgp_leftover[0]["address-family"]["with-vrf"]["ipv4"][ipv4_index]["vrf"][vrf_index]):
            
            del bgp_leftover[0]["address-family"]["with-vrf"]["ipv4"][ipv4_index]["vrf"][vrf_index]["redistribute"]

def get_global_redistribute(ned_bgp):
    for ipv4_index, ipv4_global in enumerate(ned_bgp.get("address-family", {}).get("ipv4", [])):
        if ipv4_global.get("af") == "unicast":
            return (ipv4_global.get("redistribute"), ipv4_index)
    
    return (None, None)

def get_vrf_redistribute(vrf_name, ned_bgp):
    for ipv4_index, ipv4_vrf in enumerate(ned_bgp.get("address-family", {}).get("with-vrf", {}).get("ipv4", [])):
        if ipv4_vrf.get("af") == "unicast":
            for vrf_index, vrf in enumerate(ipv4_vrf.get("vrf")):
                if vrf.get("name") == vrf_name:
                    return (vrf.get("redistribute"), ipv4_index, vrf_index)
    
    return (None, None, None)

def get_bgp_protocol(net_protocols):   
    bgp_protocol = {
        "openconfig-network-instance:identifier": "BGP",
        "openconfig-network-instance:name": "BGP"
    }

    for net_protocol in net_protocols:
        if net_protocol.get("openconfig-network-instance:identifier", "") == "BGP":
            if not "openconfig-network-instance:config" in net_protocol:
                net_protocol["openconfig-network-instance:config"] = copy.deepcopy(bgp_protocol)
            if not "openconfig-network-instance:bgp" in net_protocol:
                init_bgp(net_protocol)
            
            return net_protocol

    bgp_protocol["openconfig-network-instance:config"] = copy.deepcopy(bgp_protocol)
    init_bgp(bgp_protocol)
    net_protocols.append(bgp_protocol)

    return bgp_protocol

def init_bgp(bgp_protocol):
    bgp_protocol["openconfig-network-instance:bgp"] = {}
    get_oc_peer_groups(bgp_protocol["openconfig-network-instance:bgp"])
    get_oc_neighbors(bgp_protocol["openconfig-network-instance:bgp"])

def get_oc_peer_groups(bgp_protocol):
    if (not bgp_protocol.get("openconfig-network-instance:peer-groups", {})
        .get("openconfig-network-instance:peer-group")):
        bgp_protocol["openconfig-network-instance:peer-groups"] = {"openconfig-network-instance:peer-group": []}
        
    return bgp_protocol["openconfig-network-instance:peer-groups"]["openconfig-network-instance:peer-group"]

def get_oc_neighbors(bgp_protocol):
    if (not bgp_protocol.get("openconfig-network-instance:neighbors", {})
        .get("openconfig-network-instance:neighbor")):
        bgp_protocol["openconfig-network-instance:neighbors"] = {"openconfig-network-instance:neighbor": []}

    return bgp_protocol["openconfig-network-instance:neighbors"]["openconfig-network-instance:neighbor"]

def process_bgp_global(oc_bgp_global, bgp_config_before, bgp_config_leftover):
    bgp_before = bgp_config_before.get("bgp", {})
    
    process_routerid(oc_bgp_global, bgp_before, bgp_config_leftover)
    process_log_neighbor_changes(oc_bgp_global, bgp_before, bgp_config_leftover)
    process_bgp_distance(oc_bgp_global, bgp_config_before, bgp_config_leftover)
    process_graceful_restart(oc_bgp_global, bgp_before, bgp_config_leftover)
    process_route_selection_options(oc_bgp_global, bgp_before, bgp_config_leftover)
    process_max_paths(oc_bgp_global, bgp_before, bgp_config_before, bgp_config_leftover)
    process_listen_range(oc_bgp_global, bgp_before, bgp_config_leftover)

    if (bgp_config_leftover.get("bgp", {}).get("bestpath") != None 
        and len(bgp_config_leftover["bgp"]["bestpath"]) == 0):
        del bgp_config_leftover["bgp"]["bestpath"]
    
def process_routerid(oc_bgp_global, bgp_before, bgp_config_leftover):
    if bgp_before.get("router-id"):
        oc_bgp_global["openconfig-network-instance:config"]["openconfig-network-instance:router-id"] = bgp_before[
            "router-id"]
        
        if bgp_config_leftover.get("bgp", {}).get("router-id"):
            del bgp_config_leftover["bgp"]["router-id"]

def process_log_neighbor_changes(oc_bgp_global, bgp_before, bgp_config_leftover):
    if bgp_before.get("log-neighbor-changes") != None:
        oc_bgp_global["openconfig-network-instance:config"]["openconfig-bgp-ext:log-neighbor-changes"] = bgp_before[
            "log-neighbor-changes"]

        if bgp_config_leftover.get("bgp", {}).get("log-neighbor-changes") != None:
            del bgp_config_leftover["bgp"]["log-neighbor-changes"]

def process_bgp_distance(oc_bgp_global, bgp_config_before, bgp_config_leftover):
    bgp_distance = bgp_config_before.get("distance", {}).get("bgp", {})

    if bgp_distance.get("extern-as") and bgp_distance.get("internal-as"):
        oc_bgp_global["openconfig-network-instance:default-route-distance"] = {
            "openconfig-network-instance:config": {
                "openconfig-network-instance:external-route-distance": bgp_distance["extern-as"],
                "openconfig-network-instance:internal-route-distance": bgp_distance["internal-as"]
            }
        }

        if bgp_config_leftover.get("distance", {}).get("bgp", {}).get("extern-as") != None:
            del bgp_config_leftover["distance"]["bgp"]["extern-as"]
        if bgp_config_leftover.get("distance", {}).get("bgp", {}).get("internal-as") != None:
            del bgp_config_leftover["distance"]["bgp"]["internal-as"]
        if bgp_distance.get("local") != None:
            distance_msg = f"Extension not available. BGP local distance of {bgp_distance['local']} was not translated."
            xe_bgp_notes.append(distance_msg)

def process_graceful_restart(oc_bgp_global, bgp_before, bgp_config_leftover):
    graceful_restart = bgp_before.get("graceful-restart-conf", {}).get("graceful-restart", {})
    
    if graceful_restart.get("restart-time") != None or graceful_restart.get("stalepath-time") != None:
        init_graceful_restart(oc_bgp_global, True)
        oc_graceful_restart = oc_bgp_global["openconfig-network-instance:graceful-restart"]["openconfig-network-instance:config"]
        leftover_graceful_restart = bgp_config_leftover.get("bgp", {}).get("graceful-restart-conf", {}).get("graceful-restart", {})

        if graceful_restart.get("restart-time") != None:
            oc_graceful_restart["openconfig-network-instance:restart-time"] = graceful_restart["restart-time"]
            
            if leftover_graceful_restart.get("restart-time") != None:
                del leftover_graceful_restart["restart-time"]
        if graceful_restart.get("stalepath-time") != None:
            oc_graceful_restart["openconfig-network-instance:stale-routes-time"] = graceful_restart["stalepath-time"]
            
            if leftover_graceful_restart.get("stalepath-time") != None:
                del leftover_graceful_restart["stalepath-time"]
        
        if len(leftover_graceful_restart) == 0:
            del bgp_config_leftover["bgp"]["graceful-restart-conf"]
            del bgp_config_leftover["bgp"]["graceful-restart"]
    else:
        init_graceful_restart(oc_bgp_global, False)

def init_graceful_restart(oc_bgp_global, enabled):
    oc_bgp_global["openconfig-network-instance:graceful-restart"] = {
        "openconfig-network-instance:config": {
            "openconfig-network-instance:enabled": enabled
        }
    }

def process_route_selection_options(oc_bgp_global, bgp_before, bgp_config_leftover):
    oc_bgp_global["openconfig-network-instance:route-selection-options"] = {
        "openconfig-network-instance:config": {}
    }
    config = oc_bgp_global["openconfig-network-instance:route-selection-options"][
            "openconfig-network-instance:config"]

    if bgp_before.get("always-compare-med"):
        config["openconfig-network-instance:always-compare-med"] = True
        
        if bgp_config_leftover.get("bgp", {}).get("always-compare-med"):
            del bgp_config_leftover["bgp"]["always-compare-med"]
    else:
        config["openconfig-network-instance:always-compare-med"] = False
    
    if bgp_before.get("bestpath", {}).get("compare-routerid"):
        config["openconfig-network-instance:external-compare-router-id"] = True
        
        if bgp_config_leftover.get("bgp", {}).get("bestpath", {}).get("compare-routerid"):
            del bgp_config_leftover["bgp"]["bestpath"]["compare-routerid"]
    else:
        config["openconfig-network-instance:external-compare-router-id"] = False

def process_max_paths(oc_bgp_global, bgp_before, bgp_config_before, bgp_config_leftover):
    max_paths = bgp_config_before.get("maximum-paths", {})

    if len(max_paths) > 0:
        init_multipaths(oc_bgp_global, True)
        oc_multipath = oc_bgp_global["openconfig-network-instance:use-multiple-paths"]
        
        if max_paths.get("paths", {}).get("number-of-paths") != None:
            set_multipaths(oc_multipath, "openconfig-network-instance:ebgp", max_paths["paths"]["number-of-paths"])
            oc_multipath["openconfig-network-instance:ebgp"]["openconfig-network-instance:config"][
                "openconfig-network-instance:allow-multiple-as"] = is_allow_multipath_as(bgp_before, bgp_config_leftover)

            if bgp_config_leftover.get("maximum-paths", {}).get("paths", {}).get("number-of-paths"):
                del bgp_config_leftover["maximum-paths"]["paths"]
        if max_paths.get("ibgp", {}).get("paths", {}).get("number-of-paths") != None:
            set_multipaths(oc_multipath, "openconfig-network-instance:ibgp", max_paths["ibgp"]["paths"]["number-of-paths"])

            if bgp_config_leftover.get("maximum-paths", {}).get("ibgp", {}).get("paths", {}).get("number-of-paths"):
                del bgp_config_leftover["maximum-paths"]["ibgp"]
        
        if len(bgp_config_leftover.get("maximum-paths", {})) == 0:
            del bgp_config_leftover["maximum-paths"]
    else:
        init_multipaths(oc_bgp_global, False)

def init_multipaths(oc_bgp_global, enabled):
    oc_bgp_global["openconfig-network-instance:use-multiple-paths"] = {
        "openconfig-network-instance:config": {
            "openconfig-network-instance:enabled": enabled
        }
    }

def set_multipaths(oc_multipath, multipath_type, max_paths):
    oc_multipath[multipath_type] = {
        "openconfig-network-instance:config": {
            "openconfig-network-instance:maximum-paths": max_paths
        }
    }

def is_allow_multipath_as(bgp_before, bgp_config_leftover):
    if bgp_before.get("bestpath", {}).get("as-path", {}).get("multipath-relax"):
        if bgp_config_leftover.get("bgp", {}).get("bestpath", {}).get("as-path", {}).get("multipath-relax"):
            del bgp_config_leftover["bgp"]["bestpath"]["as-path"]
        
        return True
    
    return False

def process_listen_range(oc_bgp_global, bgp_before, bgp_config_leftover):
    oc_bgp_global["openconfig-network-instance:dynamic-neighbor-prefixes"] = {
        "openconfig-network-instance:dynamic-neighbor-prefix": []
    }
    oc_dynamic_neighbors = oc_bgp_global["openconfig-network-instance:dynamic-neighbor-prefixes"][
        "openconfig-network-instance:dynamic-neighbor-prefix"]

    for range_item in bgp_before.get("listen", {}).get("range", []):
        oc_dynamic_neighbors.append({
            "openconfig-network-instance:prefix": range_item["network-length"],
            "openconfig-network-instance:config": {
                "openconfig-network-instance:prefix": range_item["network-length"],
                "openconfig-network-instance:peer-group": range_item["peer-group"]
            }
        })

    # Assume listen range list successfully processed
    if len(bgp_config_leftover.get("bgp", {}).get("listen", {}).get("range", [])) > 0:
        del bgp_config_leftover["bgp"]["listen"]

def process_address_family_default(bgp_protocol_bgp, oc_bgp_afi, bgp_config_before, bgp_config_leftover):
    afi = bgp_config_before.get("address-family", {})
    
    for index, afi_ipv4 in enumerate(afi.get("ipv4", [])):
        if afi_ipv4.get("af") == "unicast":
            afi_ipv4_leftover = bgp_config_leftover["address-family"]["ipv4"][index]
            oc_bgp_afi.append(process_af_ipv4_unicast(afi_ipv4, afi_ipv4_leftover))
            process_neighbor_and_neighbor_tag(True, ATTR_PEER, afi_ipv4, 
                afi_ipv4_leftover, "IPV4_UNICAST")
            process_neighbor_and_neighbor_tag(True, ATTR_NEIGHBOR, afi_ipv4, 
                afi_ipv4_leftover, "IPV4_UNICAST")

            if afi_ipv4_leftover != None and afi_ipv4_leftover.get("af") and len(afi_ipv4_leftover) == 1:
                del afi_ipv4_leftover["af"]
            if afi_ipv4_leftover != None and len(afi_ipv4_leftover) == 0:
                bgp_config_leftover["address-family"]["ipv4"][index] = None

    for index, afi_vpnv4 in enumerate(afi.get("vpnv4", [])):
        if afi_vpnv4.get("af") == "unicast":
            afi_vpnv4_leftover = bgp_config_leftover["address-family"]["vpnv4"][index]
            oc_bgp_afi.append(init_oc_afi("L3VPN_IPV4_UNICAST"))
            process_neighbor_and_neighbor_tag(True, ATTR_PEER, afi_vpnv4, 
                afi_vpnv4_leftover, "L3VPN_IPV4_UNICAST")
            process_neighbor_and_neighbor_tag(True, ATTR_NEIGHBOR, afi_vpnv4, 
                afi_vpnv4_leftover, "L3VPN_IPV4_UNICAST")

            if afi_vpnv4_leftover != None and afi_vpnv4_leftover.get("af") and len(afi_vpnv4_leftover) == 1:
                del afi_vpnv4_leftover["af"]
            # bgp_config_leftover.get("address-family", {}).get("vpnv4", [])[index] = None
    
    if len(afi.get("ipv6", [])) > 0:
        xe_bgp_notes.append("AFI IPV6 unicast has not yet been implemented")
    if len(afi.get("vpnv6", [])) > 0:
        xe_bgp_notes.append("AFI L3VPN IPV6 unicast has not yet been implemented")

def process_address_family_vrf(vrf_name, bgp_protocol_bgp, oc_bgp_afi, bgp_config_before, bgp_config_leftover):
    oc_bgp_global = bgp_protocol_bgp["openconfig-network-instance:global"]
    afi_vrf = bgp_config_before.get("address-family", {}).get("with-vrf", {})

    for index, afi_ipv4 in enumerate(afi_vrf.get("ipv4", [])):
        if afi_ipv4.get("af") == "unicast":
            afi_vrf_leftover = bgp_config_leftover["address-family"]["with-vrf"]["ipv4"]
            
            for vrf_index, afi_ipv4_vrf in enumerate(afi_ipv4.get("vrf", [])):
                if afi_ipv4_vrf.get("name") == vrf_name:
                    afi_vrf_ipv4_leftover = afi_vrf_leftover[index]["vrf"][vrf_index]
                    oc_bgp_afi.append(process_af_ipv4_unicast(afi_ipv4_vrf, afi_vrf_ipv4_leftover))
                    process_bgp_distance(oc_bgp_global, afi_ipv4_vrf, afi_vrf_ipv4_leftover)
                    process_neighbor_and_neighbor_tag(True, ATTR_PEER, afi_ipv4_vrf, 
                        afi_vrf_ipv4_leftover, "IPV4_UNICAST")
                    process_neighbor_and_neighbor_tag(True, ATTR_NEIGHBOR, afi_ipv4_vrf, 
                        afi_vrf_ipv4_leftover, "IPV4_UNICAST")

                    if (afi_vrf_ipv4_leftover != None and afi_vrf_ipv4_leftover.get("name")
                        and len(afi_vrf_ipv4_leftover) == 1):
                        del afi_vrf_ipv4_leftover["name"] 

            if (afi_vrf_leftover[index] != None and afi_vrf_leftover[index].get("af") 
                and len(afi_vrf_leftover[index]) == 1):
                del afi_vrf_leftover[index]["af"]
    
    if len(bgp_config_before.get("address-family", {}).get("ipv6-with-vrf", {}).get("ipv6", [])) > 0:
        xe_bgp_notes.append("AFI IPV6 VRF unicast has not yet been implemented")

def init_oc_afi(afi_name):
    new_afi_data = {}
    new_afi_data["openconfig-network-instance:afi-safi-name"] = afi_name
    new_afi_data["openconfig-network-instance:config"] = {
        "openconfig-network-instance:afi-safi-name": afi_name,
        "openconfig-network-instance:enabled": True
    }

    return new_afi_data

def process_af_ipv4_unicast(afi_ipv4_before, afi_ipv4_after):
    afi_data = init_oc_afi("IPV4_UNICAST")
    
    if not "originate" in afi_ipv4_before.get("default-information", {}):
        return afi_data

    afi_data["openconfig-network-instance:ipv4-unicast"] = {
        "openconfig-network-instance:config": {
            "openconfig-network-instance:send-default-route": True
        }
    }

    # This funciton is used by both VRF and default instance. Default does not have name field.
    if "default-information" in afi_ipv4_after:
        del afi_ipv4_after["default-information"]
    if "name" in afi_ipv4_after and len(afi_ipv4_after) == 1:
        del afi_ipv4_after["name"]

    return afi_data

def process_neighbor_and_neighbor_tag(is_afi_safi, attr_name, bgp_before, bgp_leftover, address_family = None):
    neighbor_before = (bgp_before.get("neighbor-tag", {}).get("neighbor", []) if attr_name == ATTR_PEER 
        else bgp_before.get("neighbor", []))
    neighbor_leftover = (bgp_leftover.get("neighbor-tag", {}).get("neighbor", []) if attr_name == ATTR_PEER 
        else bgp_leftover.get("neighbor", []))

    for index, neighbor in enumerate(neighbor_before):
        if (attr_name == ATTR_PEER and common.is_valid_ip(neighbor["id"])
            or attr_name == ATTR_NEIGHBOR and not common.is_valid_ip(neighbor["id"])):
            continue

        peer_or_neighbor = get_peer_or_neighbor(attr_name, neighbor["id"])
        
        if address_family != None:
            if (peer_or_neighbor.get("openconfig-network-instance:afi-safis", {})
                .get("openconfig-network-instance:afi-safi") != None):
                peer_or_neighbor["openconfig-network-instance:afi-safis"][
                    "openconfig-network-instance:afi-safi"].append(init_oc_afi(address_family))
            else:
                peer_or_neighbor["openconfig-network-instance:afi-safis"] = {
                    "openconfig-network-instance:afi-safi": [init_oc_afi(address_family)]
                }
                
        process_send_community(neighbor, peer_or_neighbor, index, neighbor_leftover)
        process_route_reflectors(neighbor, peer_or_neighbor, index, neighbor_leftover, is_afi_safi)
        process_route_map(neighbor, peer_or_neighbor, index, neighbor_leftover, is_afi_safi)
        process_peer_and_neighbor_config(neighbor, peer_or_neighbor, index, neighbor_leftover, is_afi_safi)
        process_timers(neighbor, peer_or_neighbor, index, neighbor_leftover)
        process_transport(neighbor, peer_or_neighbor, index, neighbor_leftover)
        process_ebgp_multihop(neighbor, peer_or_neighbor, index, neighbor_leftover)

        if is_afi_safi:
            process_activate(neighbor, peer_or_neighbor, index, neighbor_leftover)
            process_as_override(neighbor, peer_or_neighbor, index, neighbor_leftover)
            process_send_label(neighbor, peer_or_neighbor, index, neighbor_leftover)

            if attr_name == ATTR_NEIGHBOR:
                process_shutdown(neighbor, peer_or_neighbor, index, neighbor_leftover)
                process_peer_group(neighbor, peer_or_neighbor, index, neighbor_leftover)
                process_ttl_security(neighbor, peer_or_neighbor, index, neighbor_leftover)
        if len(neighbor_leftover) > index and neighbor_leftover[index] != None:
            if "peer-group" in neighbor_leftover[index]:
                del neighbor_leftover[index]["peer-group"]
            if "id" in neighbor_leftover[index] and len(neighbor_leftover[index]) == 1:
                del neighbor_leftover[index]["id"]
        if (len(neighbor_leftover) > index and neighbor_leftover[index] != None
            and len(neighbor_leftover[index]) == 0):
            neighbor_leftover[index] = None

def get_peer_or_neighbor(attr_name, neighbor_id):
    if neighbor_id in peers:
        return peers[neighbor_id]
    if neighbor_id in neighbors:
        return neighbors[neighbor_id]
    
    peer_or_neighbor = {
        f"openconfig-network-instance:{attr_name}": neighbor_id,
        "openconfig-network-instance:config": {
            f"openconfig-network-instance:{attr_name}": neighbor_id
        }
    }
    
    if attr_name == ATTR_PEER:
        peers[neighbor_id] = peer_or_neighbor
    if attr_name == ATTR_NEIGHBOR:
        neighbors[neighbor_id] = peer_or_neighbor

    return peer_or_neighbor

def delete_leftover_neighbor_prop(attr_name, index, neighbor_leftover):
    if (len(neighbor_leftover) > index and neighbor_leftover[index] != None
        and neighbor_leftover[index].get(attr_name) != None):
        del neighbor_leftover[index][attr_name]

def process_send_community(neighbor, peer_group_or_neighbor, index, neighbor_leftover):
    if not neighbor.get("send-community", {}).get("send-community-where"):
        return

    peer_group_or_neighbor["openconfig-network-instance:config"][
        "openconfig-network-instance:send-community"] = neighbor["send-community"]["send-community-where"].upper()
    delete_leftover_neighbor_prop("send-community", index, neighbor_leftover)
    
def process_route_reflectors(neighbor, peer_group_or_neighbor, index, neighbor_leftover, is_afi_safi):
    if not "route-reflector-client" in neighbor and not "cluster-id" in neighbor:
        return

    new_config = {"openconfig-network-instance:config": {}}
    peer_group_or_neighbor["openconfig-network-instance:route-reflector"] = new_config

    if "route-reflector-client" in neighbor:
        new_config["openconfig-network-instance:config"][
            "openconfig-network-instance:route-reflector-client"] = True
        delete_leftover_neighbor_prop("route-reflector-client", index, neighbor_leftover)
    if "cluster-id" in neighbor and is_afi_safi:
        new_config["openconfig-network-instance:config"][
            "openconfig-network-instance:route-reflector-cluster-id"] = neighbor["cluster-id"]
        delete_leftover_neighbor_prop("cluster-id", index, neighbor_leftover)

def process_route_map(neighbor, peer_group_or_neighbor, index, neighbor_leftover, is_afi_safi):
    if not "route-map" in neighbor or len(neighbor.get("route-map", [])) == 0:
        return
    
    if is_afi_safi:
        # There should only be one in the list
        afi = peer_group_or_neighbor["openconfig-network-instance:afi-safis"][
            "openconfig-network-instance:afi-safi"][0]
        afi["openconfig-network-instance:apply-policy"] = {"openconfig-network-instance:config": {}}
        policy_config = afi["openconfig-network-instance:apply-policy"]["openconfig-network-instance:config"]
    else:
        peer_group_or_neighbor["openconfig-network-instance:apply-policy"] = {
            "openconfig-network-instance:config": {}}
        policy_config = peer_group_or_neighbor["openconfig-network-instance:apply-policy"][
            "openconfig-network-instance:config"]

    for route_map in neighbor["route-map"]:
        if route_map["direction"] == "out":
            policy_config["openconfig-network-instance:export-policy"] = [route_map["route-map-name"]]
        if route_map["direction"] == "in":
            policy_config["openconfig-network-instance:import-policy"] = [route_map["route-map-name"]]

    delete_leftover_neighbor_prop("route-map", index, neighbor_leftover)

def process_activate(neighbor, peer_group_or_neighbor, index, neighbor_leftover):
    # There should only be one in the list
    peer_group_or_neighbor["openconfig-network-instance:afi-safis"][
        "openconfig-network-instance:afi-safi"][0]["openconfig-network-instance:config"][
            "openconfig-network-instance:enabled"] = "activate" in neighbor
    delete_leftover_neighbor_prop("activate", index, neighbor_leftover)

def process_peer_and_neighbor_config(neighbor, peer_group_or_neighbor, index, neighbor_leftover, is_afi_safi):
    peer_or_neighbor_config = peer_group_or_neighbor["openconfig-network-instance:config"]

    if neighbor.get("remote-as"):
        peer_or_neighbor_config["openconfig-network-instance:peer-as"] = neighbor["remote-as"]
        delete_leftover_neighbor_prop("remote-as", index, neighbor_leftover)
    if neighbor.get("description"):
        peer_or_neighbor_config["openconfig-network-instance:description"] = neighbor["description"]
        delete_leftover_neighbor_prop("description", index, neighbor_leftover)
    if neighbor.get("password", {}).get("text"):
        peer_or_neighbor_config["openconfig-network-instance:auth-password"] = neighbor["password"]["text"]
    if neighbor.get("password", {}).get("enctype") == 7:
        peer_or_neighbor_config["openconfig-bgp-ext:password-encryption"] = 'ENCRYPTED'
    elif neighbor.get("password", {}).get("enctype") == 0:
        peer_or_neighbor_config["openconfig-bgp-ext:password-encryption"] = 'CLEARTEXT'
    if neighbor.get("password", {}):
        del neighbor_leftover[index]["password"]
    if neighbor.get("ao", {}).get("keychain-name"):
        peer_or_neighbor_config["openconfig-bgp-ext:tcpao-keychain"] = neighbor["ao"]["keychain-name"]
        del neighbor_leftover[index]["ao"]
    if is_afi_safi:
        if neighbor.get("local-as", {}).get("as-no"):
            peer_or_neighbor_config["openconfig-network-instance:local-as"] = neighbor["local-as"]["as-no"]
            delete_leftover_neighbor_prop("local-as", index, neighbor_leftover)
        if neighbor.get("remove-private-as"):
            if neighbor["remove-private-as"].get("replace-as"):
                peer_or_neighbor_config["openconfig-network-instance:remove-private-as"] = "PRIVATE_AS_REPLACE_ALL"
            elif neighbor["remove-private-as"].get("all"):
                peer_or_neighbor_config["openconfig-network-instance:remove-private-as"] = "PRIVATE_AS_REMOVE_ALL"

            delete_leftover_neighbor_prop("remove-private-as", index, neighbor_leftover)

def process_ebgp_multihop(neighbor, peer_group_or_neighbor, index, neighbor_leftover):
    if not "ebgp-multihop" in neighbor or neighbor["ebgp-multihop"].get("max-hop") == None:
        return
    
    peer_group_or_neighbor["openconfig-network-instance:ebgp-multihop"] = {
        "openconfig-network-instance:config": {
            "openconfig-network-instance:enabled": True,
            "openconfig-network-instance:multihop-ttl": neighbor["ebgp-multihop"]["max-hop"]
        }
    }
    delete_leftover_neighbor_prop("ebgp-multihop", index, neighbor_leftover)

def process_timers(neighbor, peer_group_or_neighbor, index, neighbor_leftover):
    if not "timers" in neighbor:
        return
        
    peer_group_or_neighbor["openconfig-network-instance:timers"] = {"openconfig-network-instance:config": {}}
    timers_config = peer_group_or_neighbor["openconfig-network-instance:timers"][
        "openconfig-network-instance:config"]
        
    if neighbor["timers"].get("holdtime") != None:
        timers_config["openconfig-network-instance:hold-time"] = neighbor["timers"]["holdtime"]
    if neighbor["timers"].get("keepalive-interval") != None:
        timers_config["openconfig-network-instance:keepalive-interval"] = neighbor["timers"]["keepalive-interval"]

    delete_leftover_neighbor_prop("timers", index, neighbor_leftover)

def process_transport(neighbor, peer_group_or_neighbor, index, neighbor_leftover):
    if not "transport" in neighbor and not "update-source" in neighbor:
        return

    peer_group_or_neighbor["openconfig-network-instance:transport"] = {"openconfig-network-instance:config": {}}
    transport_config = peer_group_or_neighbor["openconfig-network-instance:transport"][
        "openconfig-network-instance:config"]
    
    if "transport" in neighbor:
        if neighbor["transport"].get("path-mtu-discovery"):
            transport_config["openconfig-network-instance:mtu-discovery"] = neighbor["transport"][
                "path-mtu-discovery"].get("disable") == True
        if neighbor["transport"].get("connection-mode"):
            transport_config["openconfig-network-instance:passive-mode"] = neighbor["transport"][
                "connection-mode"] == "passive"
    if "update-source" in neighbor:
        if neighbor.get("update-source"):
            for key in neighbor["update-source"]:
                transport_config["openconfig-network-instance:local-address"] = \
                    f"{key}{neighbor['update-source'][key]}"
        
        delete_leftover_neighbor_prop("update-source", index, neighbor_leftover)

    delete_leftover_neighbor_prop("transport", index, neighbor_leftover)

def process_as_override(neighbor, peer_group_or_neighbor, index, neighbor_leftover):
    if not "as-override" in neighbor:
        return
        
    peer_group_or_neighbor["openconfig-network-instance:as-path-options"] = {
        "openconfig-network-instance:config": {
            "openconfig-network-instance:replace-peer-as": not "disable" in neighbor["as-override"]
        }
    }
    delete_leftover_neighbor_prop("as-override", index, neighbor_leftover)

def process_send_label(neighbor, peer_group_or_neighbor, index, neighbor_leftover):
    if not "send-label" in neighbor:
        return
    
    afi_safi = peer_group_or_neighbor["openconfig-network-instance:afi-safis"][
        "openconfig-network-instance:afi-safi"][0]
    afi_safi["openconfig-network-instance:afi-safi-name"] = "IPV4_LABELED_UNICAST"
    afi_safi["openconfig-network-instance:config"][
            "openconfig-network-instance:afi-safi-name"] = "IPV4_LABELED_UNICAST"
    delete_leftover_neighbor_prop("send-label", index, neighbor_leftover)

def process_shutdown(neighbor, peer_group_or_neighbor, index, neighbor_leftover):
    peer_group_or_neighbor["openconfig-network-instance:config"][
        "openconfig-network-instance:enabled"] = not "shutdown" in neighbor
    delete_leftover_neighbor_prop("shutdown", index, neighbor_leftover)

def process_peer_group(neighbor, peer_group_or_neighbor, index, neighbor_leftover):
    if not "peer-group" in neighbor:
        return
    
    peer_group_or_neighbor["openconfig-network-instance:config"][
        "openconfig-network-instance:peer-group"] = neighbor["peer-group"]
    delete_leftover_neighbor_prop("peer-group", index, neighbor_leftover)

def process_ttl_security(neighbor, peer_group_or_neighbor, index, neighbor_leftover):
    if neighbor.get("ttl-security", {}).get("hops") == None:
        return

    peer_group_or_neighbor["openconfig-network-instance:config"][
        "openconfig-bgp-ext:ttl-security"] = neighbor["ttl-security"]["hops"]
    delete_leftover_neighbor_prop("ttl-security", index, neighbor_leftover)
