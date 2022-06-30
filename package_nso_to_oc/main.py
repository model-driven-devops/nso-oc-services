#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_configuration.json, save the NSO device
configuration minus parts replaced by OpenConfig to a file named {device_name}_configuration_remaining.json,
and save the MDD OpenConfig configuration to a file named {nso_device}_openconfig.json.

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
import sys
sys.path.append('../../package_nso_to_oc')

import common
from xe import xe_system


nso_host = os.environ.get("NSO_HOST")
nso_username = os.environ.get("NSO_USERNAME", "ubuntu")
nso_password = os.environ.get("NSO_PASSWORD", "admin")
nso_device = os.environ.get("NSO_DEVICE", "xe1")
test = os.environ.get("TEST", "False")

config_before_dict = common.nso_get_device_config(nso_host, nso_username, nso_password, nso_device)
configs_leftover = copy.deepcopy(config_before_dict)
interface_ip_name_dict = common.xe_system_get_interface_ip_address(config_before_dict)

openconfig_system = xe_system.main(config_before_dict, configs_leftover, interface_ip_name_dict)


print(json.dumps(config_before_dict, indent=4))
print(json.dumps(configs_leftover, indent=4))
print(json.dumps(openconfig_system, indent=4))

oc = {"mdd:openconfig": openconfig_system}

with open(f"{nso_device}_configuration.json", "w") as b:
    b.write(json.dumps(config_before_dict, indent=4))
with open(f"{nso_device}_configuration_remaining.json", "w") as a:
    a.write(json.dumps(configs_leftover, indent=4))
with open(f"{nso_device}_openconfig.json", "w") as o:
    o.write(json.dumps(oc, indent=4))


