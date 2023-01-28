#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This package provides the tools to pull a device's configuration from an NSO server and
convert the NED structured configuration to MDD OpenConfig.

The package requires the following environment variables:
always:
- NSO_DEVICE - NSO device name for configuration translation
if pulling configs from NSO:
- NSO_URL - URL for the NSO server
- NSO_USERNAME
- NSO_PASSWORD
elif reading in from file:
- NSO_NED_FILE (path and filename)

Example of generating MDD OpenConfig System

import package_nso_to_oc
openconfig_json = package_nso_to_oc.xe.xe_system.main(package_nso_to_oc.config_before_dict,
                                                      package_nso_to_oc.configs_leftover,
                                                      package_nso_to_oc.interface_ip_name_dict)
print(openconfig_json)
"""
import copy
import json
import os
import sys

from . import common
from .xe import xe_system

if os.environ.get("NSO_URL", False) and os.environ.get("NSO_NED_FILE", False):
    print("environment variable NSO_URL or NSO_NED_FILE must be set: not both")
    exit()
elif not os.environ.get("NSO_URL", False) and not os.environ.get("NSO_NED_FILE", False):
    print("environment variable NSO_URL or NSO_NED_FILE must be set")
    exit()

nso_api_url = os.environ.get("NSO_URL", False)
nso_ned_file = os.environ.get("NSO_NED_FILE", False)
nso_username = os.environ.get("NSO_USERNAME", "ubuntu")
nso_password = os.environ.get("NSO_PASSWORD", "admin")
nso_device = os.environ.get("NSO_DEVICE", "xe1")
device_os = os.environ.get("DEVICE_OS", common.XE)
test = os.environ.get("TEST", "False")

if nso_api_url:
    config_before_dict = common.nso_get_device_config(nso_api_url, nso_username, nso_password, nso_device)
elif nso_ned_file:
    with open(nso_ned_file, "r") as f:
        config_before_dict = json.load(f)
configs_leftover = copy.deepcopy(config_before_dict)

if device_os == common.XE:
    interface_ip_name_dict = common.xe_system_get_interface_ip_address(config_before_dict)
