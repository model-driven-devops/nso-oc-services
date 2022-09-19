#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_full_ned_configuration.json, save the
NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_full_ned_configuration_remaining.json, and save the MDD OpenConfig configuration to a file named
{nso_device}_full_openconfig.json.

The script requires the following environment variables:
NSO_HOST - IP address or hostname for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation
TEST - True or False. True enables sending the OpenConfig to the NSO server after generation
"""
import copy
import json
import os

import common
from xe import main_xe
from xr import main_xr

nso_host = os.environ.get("NSO_HOST")
nso_username = os.environ.get("NSO_USERNAME", "ubuntu")
nso_password = os.environ.get("NSO_PASSWORD", "admin")
nso_device = os.environ.get("NSO_DEVICE", "xr1")
device_os = os.environ.get("DEVICE_OS", common.XR)
test = os.environ.get("TEST", "False")

config_before_dict = common.nso_get_device_config(nso_host, nso_username, nso_password, nso_device)
configs_leftover = copy.deepcopy(config_before_dict)
oc = {"mdd:openconfig": {}}

if device_os == common.XE:
    main_xe.build_xe_to_oc(config_before_dict, configs_leftover, oc)
elif device_os == common.XR:
    main_xr.build_xr_to_oc(config_before_dict, configs_leftover, oc)

config_name = "full_ned_configuration"
config_remaining_name = "full_ned_configuration_remaining"
oc_name = "full_openconfig"
common.print_and_test_configs(nso_device, config_before_dict, configs_leftover, oc, config_name, config_remaining_name, oc_name)
