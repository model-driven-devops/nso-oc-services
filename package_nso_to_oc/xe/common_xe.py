"""
Functions in here need to be in a separate file from main_xe.py to avoid cyclical dependencies
when invoking the individual features.
"""

import sys
import os
import copy
import json
from pathlib import Path

# To be able to import top-level common
sys.path.append(str(Path(__file__).resolve().parents[1]))

import common

# XE static route keys
IP_FORWARDING_LIST = "ip-route-forwarding-list"
INTF_LIST = "ip-route-interface-list"
IP_INTF_FORWARDING_LIST = "ip-route-interface-forwarding-list"
redistribute_type = {
    "ospf": "OSPF",
    "static": "STATIC",
    "connected": "DIRECTLY_CONNECTED",
    "bgp": "BGP"
}

def init_xe_configs(device_name = "xe1"):
    nso_ned_file = os.environ.get("NSO_NED_FILE", False)

    if nso_ned_file:
        with open(nso_ned_file, "r") as ned_file:
            config_before_dict = json.load(ned_file)
    else:
        (nso_api_url, nso_username, nso_password) = common.get_nso_creds()
        nso_device = os.environ.get("NSO_DEVICE", device_name)
        config_before_dict = common.nso_get_device_config(nso_api_url, nso_username, nso_password, nso_device)

    config_leftover_dict = copy.deepcopy(config_before_dict)
    interface_ip_dict = common.xe_system_get_interface_ip_address(config_before_dict)

    return (config_before_dict, config_leftover_dict, interface_ip_dict)

def process_redistribute(net_inst, redistribute, redistribute_leftover, dst_prot, dst_process_num = None):
    if not redistribute:
        return

    if (not "openconfig-network-instance:table-connections" in net_inst or
        not "openconfig-network-instance:table-connection" in net_inst["openconfig-network-instance:table-connections"]):
        
        net_inst["openconfig-network-instance:table-connections"] = {
            "openconfig-network-instance:table-connection": []
        }
    
    table_connections = net_inst["openconfig-network-instance:table-connections"][
        "openconfig-network-instance:table-connection"]

    if "bgp" in redistribute:
        create_protocol_config(table_connections, redistribute, redistribute_leftover, "bgp", dst_prot,
            dst_process_num)
    if "connected" in redistribute:
        create_protocol_config(table_connections, redistribute, redistribute_leftover, "connected", dst_prot,
            dst_process_num)
    if "static" in redistribute:
        create_protocol_config(table_connections, redistribute, redistribute_leftover, "static", dst_prot,
            dst_process_num)
    if "ospf" in redistribute:
        create_protocol_config(table_connections, redistribute, redistribute_leftover, "ospf", dst_prot,
            dst_process_num)

def create_protocol_config(table_connections, redistribute, redistribute_leftover, protocol, dst_prot,
    dst_process_num):
    
    if type(redistribute[protocol]) == list:
        updated_prot_list = []

        for prot_index, prot_item in enumerate(redistribute[protocol]):
            proto_config = append_new_to_table_connections(protocol, table_connections, dst_prot)
            if len(redistribute_leftover.get(protocol, [])) > prot_index:
                prot_item_leftover = redistribute_leftover[protocol][prot_index]
            else:
                prot_item_leftover = None

            process_protocol(proto_config, prot_item, prot_item_leftover, dst_process_num, dst_prot)

            if prot_item_leftover and len(prot_item_leftover) == 0:
                redistribute_leftover[protocol][prot_index] = None
        
        for leftover_prot in redistribute_leftover.get(protocol, []):
            if leftover_prot:
                updated_prot_list.append(leftover_prot)
        
        if len(updated_prot_list) > 0:
            redistribute_leftover[protocol] = updated_prot_list
        else:
            if redistribute_leftover != {}:
                del redistribute_leftover[protocol]
    else:
        proto_config = append_new_to_table_connections(protocol, table_connections, dst_prot)
        temp_redistribute_leftover = redistribute_leftover.get(protocol) if redistribute_leftover else None
        process_protocol(proto_config, redistribute[protocol], temp_redistribute_leftover, dst_process_num, dst_prot)

        if (redistribute_leftover and redistribute_leftover[protocol] != None 
            and len(redistribute_leftover[protocol]) == 0):
            del redistribute_leftover[protocol]

def append_new_to_table_connections(protocol, table_connections, dst_prot):
    proto_config = {
        "openconfig-network-instance:src-protocol": redistribute_type[protocol],
        "openconfig-network-instance:dst-protocol": dst_prot,
        "openconfig-network-instance:address-family": "IPV4"
    }
    proto_config_parent = copy.deepcopy(proto_config)
    proto_config_parent["openconfig-network-instance:config"] = proto_config
    table_connections.append(proto_config_parent)

    return proto_config

def process_protocol(proto_config, redistribute_protocol, redistribute_protocol_leftover, dst_process_num, dst_prot):

    process_src_protocol(proto_config, redistribute_protocol, redistribute_protocol_leftover, "id")
    process_src_protocol(proto_config, redistribute_protocol, redistribute_protocol_leftover, "as-no")
    if dst_process_num != None:
        proto_config["openconfig-network-instance-ext:dst-protocol-process-number"] = dst_process_num
    if "route-map" in redistribute_protocol:
        proto_config["openconfig-network-instance:import-policy"] = redistribute_protocol["route-map"]

        if redistribute_protocol_leftover and redistribute_protocol_leftover.get("route-map"):
            del redistribute_protocol_leftover["route-map"]

def process_src_protocol(proto_config, redistribute_protocol, redistribute_protocol_leftover, src_key):
    if src_key in redistribute_protocol:
        proto_config["openconfig-network-instance-ext:src-protocol-process-number"] = redistribute_protocol[src_key]

        if redistribute_protocol_leftover and redistribute_protocol_leftover.get(src_key):
            del redistribute_protocol_leftover[src_key]
