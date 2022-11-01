#! /usr/bin/env python3

"""
This module should only ever be called by main.py
"""

from xr import xr_system

def build_xr_to_oc(config_before_dict, configs_leftover, oc, translation_notes: list):
    openconfig_system = xr_system.main(config_before_dict, configs_leftover, translation_notes)
    oc['mdd:openconfig'].update(openconfig_system)
