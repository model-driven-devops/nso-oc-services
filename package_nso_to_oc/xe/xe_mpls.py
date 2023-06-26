#! /usr/bin/env python3
"""
This script is used by xe_network_instances.py to translate MPLS configs from NED to OC.
"""

from importlib.util import find_spec

if (find_spec("package_nso_to_oc") is not None):
    from package_nso_to_oc import common
else:
    import common

mpls_notes = []


def configure_xe_mpls(net_inst, config_before, config_leftover, network_instances_notes):
    if net_inst["openconfig-network-instance:config"]["openconfig-network-instance:name"] == "management":
        return
    
    mpls_before = config_before.get("tailf-ned-cisco-ios:mpls", {})
    mpls_leftover = config_leftover.get("tailf-ned-cisco-ios:mpls", {})
    process_propagate_ttl(net_inst, mpls_before, mpls_leftover)
    process_mpls_intf(net_inst, config_before, config_leftover, mpls_before, mpls_leftover)
    process_ldp(net_inst, config_before, mpls_before, mpls_leftover)
    network_instances_notes += mpls_notes


def process_propagate_ttl(net_inst, mpls_before, mpls_leftover):
    propagate_ttl = mpls_before.get("mpls-ip-conf", {}).get("ip", {}).get("propagate-ttl-conf", {}).get("propagate-ttl")
    
    if propagate_ttl == None:
        return
    
    mpls_global = get_global(get_mpls(net_inst))
    
    if not mpls_global.get("openconfig-network-instance:config"):
        mpls_global["openconfig-network-instance:config"] = {}

    if propagate_ttl:
        mpls_global["openconfig-network-instance:config"]["openconfig-network-instance:ttl-propagation"] = True
    elif propagate_ttl == False:
        mpls_global["openconfig-network-instance:config"]["openconfig-network-instance:ttl-propagation"] = True
        
    if len(mpls_leftover.get("mpls-ip-conf", {}).get("ip", {}).get("propagate-ttl-conf", {})) > 0:
        del mpls_leftover["mpls-ip-conf"]


def process_mpls_intf(net_inst, config_before, config_leftover, mpls_before, mpls_leftover):
    if mpls_before.get("ip") == False:
        raise ValueError("Invalid value of false for global MPLS IP")
    if mpls_leftover.get("ip") != None:
        del mpls_leftover["ip"]

    for intf_type in config_before.get("tailf-ned-cisco-ios:interface", {}):
        for intf_num, current_intf in enumerate(config_before["tailf-ned-cisco-ios:interface"].get(intf_type, [])):
            if type(current_intf) == dict and current_intf.get("mpls", {}).get("ip"):
                set_mpls_interface(net_inst, intf_type, current_intf.get("name", ""))

                leftover_intf = common.get_index_or_default(
                    config_leftover.get("tailf-ned-cisco-ios:interface", {}).get(intf_type, {}), intf_num)
                if leftover_intf.get("mpls", {}).get("ip", None) != None:
                    del leftover_intf["mpls"]


def set_mpls_interface(net_inst, intf_type, current_intf_name, mpls_enabled = True):
    (intf_num, sub_intf_name) = common.get_interface_number_split(current_intf_name)
    intf_id = f"{intf_type}{intf_num}"
    get_global_intf_attr(get_global(get_mpls(net_inst))).append({
        "openconfig-network-instance:interface-id": intf_id,
        "openconfig-network-instance:config": {
            "openconfig-network-instance:interface-id": intf_id,
            "openconfig-network-instance:mpls-enabled": True
        },
        "openconfig-network-instance:interface-ref":{
            "openconfig-network-instance:config":{
                "openconfig-network-instance:interface": intf_id,
                "openconfig-network-instance:subinterface": sub_intf_name
            }
        }
    })


def process_ldp(net_inst, config_before, mpls_before, mpls_leftover):
    if not mpls_before.get("ldp"):
        return
    
    ldp_before = mpls_before["ldp"]
    net_inst_mpls_ldp = get_net_inst_ldp(get_signaling_prot(get_mpls(net_inst)))
    process_router_id(net_inst_mpls_ldp, config_before, ldp_before, mpls_leftover)
    process_graceful_restart(net_inst_mpls_ldp, ldp_before, mpls_leftover)
    process_discovery(net_inst_mpls_ldp, ldp_before, mpls_leftover)

    if mpls_leftover.get("ldp") != None and len(mpls_leftover["ldp"]) == 0:
        del mpls_leftover["ldp"]


def process_router_id(net_inst_mpls_ldp, config_before, ldp_before, mpls_leftover):
    router_id = ldp_before.get("router-id", {})

    if len(router_id) == 0:
        return
    if not router_id.get("interface"):
        raise "MPLS router-id without an interface."
    if not router_id.get("force"):
        raise "MPLS router-id without force."
    
    (intf_type, intf_num) = common.get_interface_type_number_and_subinterface(router_id["interface"])

    for current_intf in config_before["tailf-ned-cisco-ios:interface"].get(intf_type, []):
        current_ip = current_intf.get("ip", {}).get("address", {}).get("primary", {}).get("address", None)

        if not current_ip:
            continue
        if current_intf.get("name", None) == intf_num:
            get_ldp_global(net_inst_mpls_ldp)["openconfig-network-instance:config"] = {
                "openconfig-network-instance:lsr-id": current_ip
            }

            if mpls_leftover.get("ldp", {}).get("router-id") != None:
                del mpls_leftover["ldp"]["router-id"]

            return


def process_graceful_restart(net_inst_mpls_ldp, ldp_before, mpls_leftover):
    if ldp_before.get("graceful-restart-enable", {}).get("graceful-restart"):
        get_ldp_global(net_inst_mpls_ldp)["openconfig-network-instance:graceful-restart"] = {
            "openconfig-network-instance:config": {
                "openconfig-network-instance:enabled": True
            }
        }
        
        if mpls_leftover.get("ldp", {}).get("graceful-restart-enable", {}).get("graceful-restart") != None:
            del mpls_leftover["ldp"]["graceful-restart-enable"]


def process_discovery(net_inst_mpls_ldp, ldp_before, mpls_leftover):
    if not ldp_before.get("discovery",{}).get("hello"):
        return
    
    hello = ldp_before["discovery"]["hello"]

    if hello.get("holdtime") != None:
        get_ldp_intf_attr(net_inst_mpls_ldp)["openconfig-network-instance:config"][
            "openconfig-network-instance:hello-holdtime"] = hello["holdtime"]
        
        if mpls_leftover.get("ldp", {}).get("discovery", {}).get("hello", {}).get("holdtime") != None:
            del mpls_leftover["ldp"]["discovery"]["hello"]["holdtime"]
    if hello.get("interval") != None:
        get_ldp_intf_attr(net_inst_mpls_ldp)["openconfig-network-instance:config"][
            "openconfig-network-instance:hello-interval"] = hello["interval"]
        
        if mpls_leftover.get("ldp", {}).get("discovery", {}).get("hello", {}).get("interval") != None:
            del mpls_leftover["ldp"]["discovery"]["hello"]["interval"]
    
    if (mpls_leftover.get("ldp", {}).get("discovery", {}).get("hello") != None 
        and len(mpls_leftover.get("ldp", {}).get("discovery", {}).get("hello", {})) == 0):
        del mpls_leftover["ldp"]["discovery"]["hello"]
    if (mpls_leftover.get("ldp", {}).get("discovery") != None 
        and len(mpls_leftover.get("ldp", {}).get("discovery", {})) == 0):
        del mpls_leftover["ldp"]["discovery"]


def get_mpls(net_inst):
    if not net_inst.get("openconfig-network-instance:mpls"):
        net_inst["openconfig-network-instance:mpls"] = {}

    return net_inst["openconfig-network-instance:mpls"]


def get_global(net_inst_mpls):
    if not net_inst_mpls.get("openconfig-network-instance:global"):
        net_inst_mpls["openconfig-network-instance:global"] = {}
    
    return net_inst_mpls["openconfig-network-instance:global"]


def get_global_intf_attr(net_inst_mpls):
    if not net_inst_mpls.get("openconfig-network-instance:interface-attributes"):
        net_inst_mpls["openconfig-network-instance:interface-attributes"] = {
            "openconfig-network-instance:interface": []
        }
    
    return net_inst_mpls["openconfig-network-instance:interface-attributes"]["openconfig-network-instance:interface"]


def get_signaling_prot(net_inst_mpls):
    if not net_inst_mpls.get("openconfig-network-instance:signaling-protocols"):
        net_inst_mpls["openconfig-network-instance:signaling-protocols"] = {}
    
    return net_inst_mpls["openconfig-network-instance:signaling-protocols"]


def get_net_inst_ldp(signaling_prot):
    if not signaling_prot.get("openconfig-network-instance:ldp"):
        signaling_prot["openconfig-network-instance:ldp"] = {}

    return signaling_prot["openconfig-network-instance:ldp"]


def get_ldp_global(net_inst_ldp):
    if not net_inst_ldp.get("openconfig-network-instance:global"):
        net_inst_ldp["openconfig-network-instance:global"] = {}

    return net_inst_ldp["openconfig-network-instance:global"]


def get_ldp_intf_attr(net_inst_ldp):
    if not net_inst_ldp.get("openconfig-network-instance:interface-attributes"):
        net_inst_ldp["openconfig-network-instance:interface-attributes"] = {
            "openconfig-network-instance:config": {}
        }

    return net_inst_ldp["openconfig-network-instance:interface-attributes"]

