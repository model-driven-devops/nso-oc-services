#! /usr/bin/env python3

"""
This module should only ever be called by main.py
"""

import sys

import common
from xe import xe_network_instances
from xe import xe_vlans
from xe import xe_interfaces
from xe import xe_system
from xe import xe_stp

def build_xe_to_oc(config_before_dict: dict, configs_leftover: dict, oc: dict) -> None:
    interface_ip_name_dict = common.xe_system_get_interface_ip_address(config_before_dict)
    openconfig_interfaces = xe_interfaces.main(config_before_dict, configs_leftover)
    openconfig_network_instances = xe_network_instances.main(config_before_dict, configs_leftover)
    openconfig_network_instance_default_vlans = xe_vlans.main(config_before_dict, configs_leftover)
    openconfig_network_instances["openconfig-network-instance:network-instances"][
        "openconfig-network-instance:network-instance"][0].update(
        openconfig_network_instance_default_vlans["openconfig-network-instance:network-instances"][
            "openconfig-network-instance:network-instance"][0]["openconfig-network-instance:vlans"])
    openconfig_system = xe_system.main(config_before_dict, configs_leftover, interface_ip_name_dict)
    openconfig_stp = xe_stp.main(config_before_dict, configs_leftover)
    oc['mdd:openconfig'].update(openconfig_stp)
    oc['mdd:openconfig'].update(openconfig_system)
    oc['mdd:openconfig'].update(openconfig_network_instances)
    oc['mdd:openconfig'].update(openconfig_interfaces)
