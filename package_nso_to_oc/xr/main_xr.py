#! /usr/bin/env python3

"""
This module should only ever be called by main.py
"""

from importlib.util import find_spec

if (find_spec("package_nso_to_oc") is not None):
    from package_nso_to_oc import common
    from package_nso_to_oc.xr import xr_system, xr_interfaces, xr_acls
else:
    import common
    from xr import xr_system, xr_interfaces, xr_acls

def build_xr_to_oc(config_before_dict, configs_leftover, oc, translation_notes: list):
    openconfig_interfaces = xr_interfaces.main(config_before_dict, configs_leftover, translation_notes)
    openconfig_acls = xr_acls.main(config_before_dict, configs_leftover, translation_notes)
    openconfig_system = xr_system.main(config_before_dict, configs_leftover, translation_notes)
    oc['mdd:openconfig'].update(openconfig_system)
    oc['mdd:openconfig'].update(openconfig_interfaces)
    oc['mdd:openconfig'].update(openconfig_acls)

    # return added for direct calls from ansible-mdd
    return common.prune_configs(oc)