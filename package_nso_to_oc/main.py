#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_full_ned_configuration.json, save the
NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_full_ned_configuration_remaining.json, and save the MDD OpenConfig configuration to a file named
{nso_device}_full_openconfig.json.

The script requires the following environment variables:
always:
- NSO_DEVICE - NSO device name for configuration translation
- TEST - True or False (default False). True enables sending the OpenConfig to the NSO server after generation
if pulling configs from NSO:
- NSO_URL - URL for the NSO server
- NSO_USERNAME
- NSO_PASSWORD
elif reading in from file:
- NSO_NED_FILE (path and filename)
"""

import sys
import copy
import json
import os
from importlib.util import find_spec
from pathlib import Path, os as path_os

def main():
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

    # Append any pertinent notes here. This will be printed out in output_data directory
    translation_notes = []
    if nso_api_url:
        config_before_dict = common.nso_get_device_config(nso_api_url, nso_username, nso_password, nso_device)
    elif nso_ned_file:
        with open(nso_ned_file, "r") as f:
            config_before_dict = json.load(f)
    configs_leftover = copy.deepcopy(config_before_dict)
    oc = {"mdd:openconfig": {}}

    if device_os == common.XE:
        main_xe.build_xe_to_oc(config_before_dict, configs_leftover, oc, translation_notes)
    elif device_os == common.XR:
        main_xr.build_xr_to_oc(config_before_dict, configs_leftover, oc, translation_notes)

    config_name = ""
    config_remaining_name = "_remaining"
    oc_name = "_openconfig"
    common.print_and_test_configs(nso_device, config_before_dict, configs_leftover, oc, config_name, 
        config_remaining_name, oc_name, translation_notes)

if __name__ == '__main__':
    sys.path.append(".")
    sys.path.append("../")
    sys.path.append("../../")
    sys.path.append("../../../")

    # Python won't let us place these duplicate imports in a function...
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import main_xe
        from package_nso_to_oc.xr import main_xr
        from package_nso_to_oc import common
    else:
        import common
        from xe import main_xe
        from xr import main_xr
        
    main()
else:
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import main_xe
        from package_nso_to_oc.xr import main_xr
        from package_nso_to_oc import common
    else:
        import common
        from xe import main_xe
        from xr import main_xr
