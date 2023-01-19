"""
Functions in here need to be in a separate file from main_xe.py to avoid cyclical dependencies
when invoking the individual features.
"""

import sys
import os
import copy
from pathlib import Path

# To be able to import top-level common
sys.path.append(str(Path(__file__).resolve().parents[1]))

import common

# XE static route keys
IP_FORWARDING_LIST = "ip-route-forwarding-list"
INTF_LIST = "ip-route-interface-list"
IP_INTF_FORWARDING_LIST = "ip-route-interface-forwarding-list"

def init_xe_configs(device_name = "xe1"):
    (nso_api_url, nso_username, nso_password) = common.get_nso_creds()
    nso_device = os.environ.get("NSO_DEVICE", device_name)
    config_before_dict = common.nso_get_device_config(nso_api_url, nso_username, nso_password, nso_device)
    config_leftover_dict = copy.deepcopy(config_before_dict)
    interface_ip_dict = common.xe_system_get_interface_ip_address(config_before_dict)

    return (config_before_dict, config_leftover_dict, interface_ip_dict)
