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
import sys

sys.path.append('../../package_nso_to_oc')

import common

# TODO Move OS specific logic to respective modules
from xe import xe_network_instances
from xe import xe_vlans
from xe import xe_interfaces
from xe import xe_system
from xr import xr_system

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
    openconfig_network_instances = xe_network_instances.main(config_before_dict, configs_leftover)
    openconfig_network_instance_default_vlans = xe_vlans.main(config_before_dict, configs_leftover)
    openconfig_network_instances["openconfig-network-instance:network-instances"][
        "openconfig-network-instance:network-instance"][0].update(
        openconfig_network_instance_default_vlans["openconfig-network-instance:network-instances"][
            "openconfig-network-instance:network-instance"][0]["openconfig-network-instance:vlans"])
    openconfig_interfaces = xe_interfaces.main(config_before_dict, configs_leftover)
    openconfig_system = xe_system.main(config_before_dict, configs_leftover, interface_ip_name_dict)
elif device_os == common.XR:
    openconfig_system = xr_system.main(config_before_dict, configs_leftover)

oc = {"mdd:openconfig": {}}
oc['mdd:openconfig'].update(openconfig_system)

if device_os != common.XR:
    oc['mdd:openconfig'].update(openconfig_network_instances)
    oc['mdd:openconfig'].update(openconfig_interfaces)

print(json.dumps(oc, indent=4))

with open(f"{nso_device}_full_ned_configuration.json", "w") as before:
    before.write(json.dumps(config_before_dict, indent=4))
with open(f"{nso_device}_full_ned_configuration_remaining.json", "w") as after:
    after.write(json.dumps(configs_leftover, indent=4))
with open(f"{nso_device}_full_openconfig.json", "w") as o:
    o.write(json.dumps(oc, indent=4))
