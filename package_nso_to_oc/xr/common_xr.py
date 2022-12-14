"""
Functions in here need to be in a separate file from main_xr.py to avoid cyclical dependencies
when invoking the individual features.
"""

import sys
import os
import copy
from pathlib import Path

# To be able to import top-level common
sys.path.append(str(Path(__file__).resolve().parents[1]))

import common

def init_xr_configs(device_name = "xr1"):
    (nso_api_url, nso_username, nso_password) = common.get_nso_creds()
    nso_device = os.environ.get("NSO_DEVICE", device_name)
    config_before_dict = common.nso_get_device_config(nso_api_url, nso_username, nso_password, nso_device)
    config_leftover_dict = copy.deepcopy(config_before_dict)

    return (config_before_dict, config_leftover_dict)
