#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This package provides the tools to pull a device's configuration from an NSO server and
convert the NED structured configuration to MDD OpenConfig.

The package requires the following environment variables:
NSO_HOST - IP address or hostname for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation

Example of generating MDD OpenConfig System

import package_nso_to_oc
openconfig_json = package_nso_to_oc.xe.xe_system.main(package_nso_to_oc.config_before_dict,
                                                      package_nso_to_oc.configs_leftover,
                                                      package_nso_to_oc.interface_ip_name_dict)
print(openconfig_json)
"""
import copy
import os

from . import common
from .xe import xe_system

if not os.environ.get("NSO_HOST", False):
    print("environment variable NSO_HOST must be set")
    exit()

nso_host = os.environ.get("NSO_HOST")
nso_username = os.environ.get("NSO_USERNAME", "ubuntu")
nso_password = os.environ.get("NSO_PASSWORD", "admin")
nso_device = os.environ.get("NSO_DEVICE", "xe1")
device_os = os.environ.get("DEVICE_OS", common.XE)
test = os.environ.get("TEST", "False")

config_before_dict = common.nso_get_device_config(nso_host, nso_username, nso_password, nso_device)
configs_leftover = copy.deepcopy(config_before_dict)

if device_os == common.XE:
    interface_ip_name_dict = common.xe_system_get_interface_ip_address(config_before_dict)
