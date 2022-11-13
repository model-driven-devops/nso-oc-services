"""
Functions in here need to be in a separate file from main_xr.py to avoid cyclical dependencies
when invoking the individual features.
"""

import sys
import os
import copy
from typing import Tuple
import re
from pathlib import Path, os as path_os

# To be able to import top-level common
sys.path.append(str(Path(__file__).resolve().parents[1]))

import common


def xr_get_interface_type_number_and_subinterface(interface: str) -> Tuple[str, str]:
    """
    Receive full interface name. Returns interface type and number.
    :param interface: full interface name
    :return: tuple of interface type, interface number.subinterface number
    """
    rt = re.search(r'\D+', interface)
    interface_name = rt.group(0)
    rn = re.search(r'[0-9]+(\/[0-9]+)*(\.[0-9]+)*', interface)
    interface_number = rn.group(0)
    return interface_name, interface_number


def init_xr_configs(device_name = "xr1") -> tuple:
    (nso_host, nso_username, nso_password) = common.get_nso_creds()
    nso_device = os.environ.get("NSO_DEVICE", device_name)
    config_before_dict = common.nso_get_device_config(nso_host, nso_username, nso_password, nso_device)
    config_leftover_dict = copy.deepcopy(config_before_dict)

    return (config_before_dict, config_leftover_dict)
