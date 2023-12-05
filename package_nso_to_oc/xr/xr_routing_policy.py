#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_network_instances.json,
save the NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_ned_configuration_remaining_network_instances.json, and save the MDD OpenConfig configuration to a file
named {nso_device}_openconfig_routing_policies.json.

The script requires the following environment variables:
NSO_HOST - IP address or hostname for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation
TEST - True or False. True enables sending the OpenConfig to the NSO server after generation
"""

import sys
from importlib.util import find_spec
import re

routing_policy_notes = []
openconfig_routing_policies = {
    "openconfig-routing-policy:routing-policy": {
        "openconfig-routing-policy:defined-sets": {
            "openconfig-bgp-policy:bgp-defined-sets": {},
            "openconfig-routing-policy:tag-sets": {
                "openconfig-routing-policy:tag-set": []
            }
        },
        "openconfig-routing-policy:policy-definitions": {
            "openconfig-routing-policy:policy-definition": []
        }
    }
}
# OC has an additional "NOPEER" BGP community member, which is not support in XR.
well_known_members = {
    "no-export": "NO_EXPORT",
    "no-advertise": "NO_ADVERTISE",
    "local-as": "NO_EXPORT_SUBCONFED"
}
policy_results = {
    "permit": "ACCEPT_ROUTE",
    "deny": "REJECT_ROUTE"
}
port_operators = ["range", "eq", "lt", "gt", "neq"]
regex_ipv4_masklength_range = re.compile(r'([0-9]{1,2})\.\.([0-9]{1,2})')
regex_meta = {'[', '\\', '.', '^', '$', '*', '+', '?', '{', '|', '('}
INLINE = "INLINE"
REFERENCE = "REFERENCE"
ADD = "ADD"
REPLACE = "REPLACE"
REMOVE = "REMOVE"
ACL_STD_TYPE = "ACL_IPV4_STANDARD"
ACL_EXT_TYPE = "ACL_IPV4"

def xr_routing_policy(config_before, config_after):
    process_prefix_sets(config_before, config_after)
    process_as_path_sets(config_before, config_after)
    process_community_sets(config_before, config_after)
    process_ext_community_sets(config_before, config_after)
    process_policy_definitions(config_before, config_after)

def process_prefix_sets(config_before, config_after):
    prefix_sets = {"openconfig-routing-policy:prefix-sets": {"openconfig-routing-policy:prefix-set": []}}
    xr_prefixes = config_before.get("tailf-ned-cisco-ios-xr:prefix-set", {})
    xr_prefixes_after = config_after.get("tailf-ned-cisco-ios-xr:prefix-set", {})
    prefixes_list = []

    for prefix_index, prefix in enumerate(xr_prefixes):
        new_prefix_set = {
            "openconfig-routing-policy:name": prefix.get("name"),
            "openconfig-routing-policy:config": {
                "openconfig-routing-policy:name": prefix.get("name"),
                "openconfig-routing-policy:mode": "IPV4"
            },
            "openconfig-routing-policy:prefixes": {"openconfig-routing-policy:prefix": []}
        }
        prefixes = new_prefix_set["openconfig-routing-policy:prefixes"]["openconfig-routing-policy:prefix"]
        seq_list_after = common.get_index_or_default(xr_prefixes_after, prefix_index, {}).get("set", [])
        
        for seq_index, seq in enumerate(prefix.get("set", [])):
            split_value = seq["value"].split(" ")
            ip = split_value[0]
            if len(split_value) == 1:  # if there's no operator, e.g., "44.4.0.0/16"
                if "/" in ip:
                    masklength = ip.split("/")[1]
                else:
                    masklength = "32"
            else:  # if there's an operator, e.g., "eq", "le", or "ge"
                operator = split_value[1]
                masklength = split_value[2]
                
                # handle different operators
                if operator == "eq":
                    masklength = masklength
                elif operator == "le":
                    masklength = "0.." + masklength
                elif operator == "ge":
                    masklength = masklength + "..32"
            new_prefix = {
                "openconfig-routing-policy:ip-prefix": ip,
                "openconfig-routing-policy:masklength-range": masklength,
                "openconfig-routing-policy:config": {
                    "openconfig-routing-policy:ip-prefix": ip,
                    "openconfig-routing-policy:masklength-range": masklength,
                    "openconfig-routing-policy-ext:policy_action": 'PERMIT_ROUTE'
                }
            }

            prefixes.append(new_prefix)

            # Ensure the value we're nullifying does exist
            if common.get_index_or_default(seq_list_after, seq_index, None):
                seq_list_after[seq_index] = None

        prefix_sets["openconfig-routing-policy:prefix-sets"]["openconfig-routing-policy:prefix-set"].append(new_prefix_set)
        common.get_index_or_default(xr_prefixes_after, prefix_index, {})["name"] = None

    for prefix_item in config_after.get("tailf-ned-cisco-ios-xr:ip", {}).get("prefix-list", {}).get("prefixes", []):
        if "name" in prefix_item and prefix_item["name"]:
            prefixes_list.append(prefix_item)

    if len(prefixes_list) > 0:
        config_after["tailf-ned-cisco-ios-xr:ip"]["prefix-list"]["prefixes"] = prefixes_list
    elif "prefixes" in config_after.get("tailf-ned-cisco-ios-xr:ip", {}).get("prefix-list", {}):
        del config_after["tailf-ned-cisco-ios-xr:ip"]["prefix-list"]["prefixes"]

    openconfig_routing_policies["openconfig-routing-policy:routing-policy"]["openconfig-routing-policy:defined-sets"].update(prefix_sets)

# TODO: Add support for as-path-lists
def process_as_path_sets(config_before, config_after):
    as_path_sets = {"openconfig-bgp-policy:as-path-sets": {"openconfig-bgp-policy:as-path-set": []}}
    access_list = config_before.get("tailf-ned-cisco-ios-xr:ip", {}).get("as-path", {}).get("access-list", [])
    access_list_after = config_after.get("tailf-ned-cisco-ios-xr:ip", {}).get("as-path", {}).get("access-list", [])
    all_processed = True
    updated_access_list = []

    for access_index, access in enumerate(access_list):
        new_path_set = {
            "openconfig-bgp-policy:as-path-set-name": access.get("name"),
            "openconfig-bgp-policy:config": {
                "openconfig-bgp-policy:as-path-set-name": access.get("name"),
                "openconfig-bgp-policy:as-path-set-member": []
            }
        }
        members = new_path_set["openconfig-bgp-policy:config"]["openconfig-bgp-policy:as-path-set-member"]
        rule_list_after = common.get_index_or_default(access_list_after, access_index, {}).get("as-path-rule", [])

        for rule_index, rule in enumerate(access.get("as-path-rule", [])):
            if not "operation" in rule:
                continue
            if rule["operation"] == "deny":
                all_processed = False
                routing_policy_notes.append(
f"""
AS Path Name: {access.get("name")}
Rule: {rule.get("rule")}
This rule contains a deny operation, which is not supported in OpenConfig. Translation, of the entire list, to OC will be skipped.
""")
                continue

            members.append(rule["rule"])

            # Ensure the value we're nullifying does exist
            if common.get_index_or_default(rule_list_after, rule_index, None):
                rule_list_after[rule_index] = None

        if all_processed:
            as_path_sets["openconfig-bgp-policy:as-path-sets"]["openconfig-bgp-policy:as-path-set"].append(new_path_set)
            common.get_index_or_default(access_list_after, access_index, {})["name"] = None
    
    for access_list_item in config_after.get("tailf-ned-cisco-ios-xr:ip", {}).get("as-path", {}).get("access-list", []):
        if "name" in access_list_item and access_list_item["name"]:
            updated_access_list.append(access_list_item)
    
    if len(updated_access_list) > 0:
        config_after["tailf-ned-cisco-ios-xr:ip"]["as-path"]["access-list"] = updated_access_list
    elif "access-list" in config_after.get("tailf-ned-cisco-ios-xr:ip", {}).get("as-path", {}):
        del config_after["tailf-ned-cisco-ios-xr:ip"]["as-path"]["access-list"]

    openconfig_routing_policies["openconfig-routing-policy:routing-policy"]["openconfig-routing-policy:defined-sets"]["openconfig-bgp-policy:bgp-defined-sets"].update(as_path_sets)


def process_community_sets(config_before, config_after):
    community_sets = {"openconfig-bgp-policy:community-sets": {"openconfig-bgp-policy:community-set": []}}
    community_list = config_before.get("tailf-ned-cisco-ios-xr:community-set", {})
    community_list_after = config_after.get("tailf-ned-cisco-ios-xr:community-set", {})
    process_community_members(community_sets, "number", community_list, community_list_after)
    process_community_members(community_sets, "standard", community_list, community_list_after)
    process_community_members(community_sets, "expanded", community_list, community_list_after)
    openconfig_routing_policies["openconfig-routing-policy:routing-policy"]["openconfig-routing-policy:defined-sets"]["openconfig-bgp-policy:bgp-defined-sets"].update(community_sets)


def process_community_members(community_sets, type, community_list, community_list_after):
    all_processed = True
    updated_community_list = []
    name_or_num_key = "no" if type == "number" else "name"
    for community_index, community in enumerate(community_list):
        new_community_set = {
            "openconfig-bgp-policy:community-set-name": community.get(name_or_num_key),
            "openconfig-bgp-policy:config": {
                "openconfig-bgp-policy:community-set-name": community.get(name_or_num_key),
                "openconfig-bgp-policy:match-set-options": "ANY", # IOS only supports ANY
                "openconfig-bgp-policy:community-member": []
            }
        }
        
        members = new_community_set["openconfig-bgp-policy:config"]["openconfig-bgp-policy:community-member"]
        entry_after = common.get_index_or_default(community_list_after, community_index, {})
        for entry_index, entry in enumerate(community.get("set", [])):
            if not "value" in entry:
                continue
            if entry["value"].startswith("deny"):
                all_processed = False
                routing_policy_notes.append(
f"""
Community Name: {community.get(name_or_num_key)}
Community Type: {type}
Entry: {entry["value"]}
This entry contains a deny operation, which is not supported in OpenConfig. Translation, of the entire list, to OC will be skipped.
""")
                continue

            member = entry["value"][entry["value"].find(' ') + 1:]
            members.append(well_known_members.get(member, member))

            # Ensure the value we're nullifying does exist
            if common.get_index_or_default(entry_after, entry_index, None):
                entry_after[entry_index] = None

        if all_processed:
            community_sets["openconfig-bgp-policy:community-sets"]["openconfig-bgp-policy:community-set"].append(new_community_set)
            common.get_index_or_default(community_list_after, community_index, {})[name_or_num_key] = None
            common.get_index_or_default(community_list_after, community_index, {})["set"] = None
    
    for community_list_item in community_list_after:
        if name_or_num_key in community_list_item and community_list_item[name_or_num_key]:
            updated_community_list.append(community_list_item)
    
    if len(updated_community_list) > 0:
        community_list_after[type] = updated_community_list
    elif type in community_list_after:
        del community_list_after[type]


def process_ext_community_sets(config_before, config_after):
    ext_community_sets = {"openconfig-bgp-policy:ext-community-sets": {"openconfig-bgp-policy:ext-community-set": []}}
    ext_community_list = config_before.get("tailf-ned-cisco-ios-xr:extcommunity-set", {}).get("opaque", [])
    ext_community_list_after = config_after.get("tailf-ned-cisco-ios-xr:extcommunity-set", {}).get("opaque", [])
    process_ext_community_members(ext_community_sets, "expanded", ext_community_list, ext_community_list_after)
    openconfig_routing_policies["openconfig-routing-policy:routing-policy"]["openconfig-routing-policy:defined-sets"]["openconfig-bgp-policy:bgp-defined-sets"].update(ext_community_sets)


def process_ext_community_members(ext_community_sets, type, ext_community_list, ext_community_list_after):
    all_processed = True
    updated_community_list = []


    for ext_community_index, ext_community in enumerate(ext_community_list):
        new_ext_community_set = {
            "openconfig-bgp-policy:ext-community-set-name": ext_community.get("name"),
            "openconfig-bgp-policy:config": {
                "openconfig-bgp-policy:ext-community-set-name": ext_community.get("name"),
                "openconfig-bgp-policy:ext-community-member": []
            }
        }
        
        members = new_ext_community_set["openconfig-bgp-policy:config"]["openconfig-bgp-policy:ext-community-member"]
        entry_after = common.get_index_or_default(ext_community_list_after, ext_community_index, {})
        for entry_index, entry in enumerate(ext_community.get("set", [])):
            if not "value" in entry:
                continue
            if entry["value"].startswith("deny"):
                all_processed = False
                routing_policy_notes.append(
f"""
Community Name: {ext_community.get("name")}
Community Type: {type}
Entry: {entry["value"]}
This entry contains a deny operation, which is not supported in OpenConfig. Translation, of the entire list, to OC will be skipped.
""")
                continue

            member = entry["value"][entry["value"].find(' ') + 1:]
            members.append(well_known_members.get(member, member))

            # Ensure the value we're nullifying does exist
            if common.get_index_or_default(entry_after, entry_index, None):
                entry_after[entry_index] = None

        if all_processed:
            ext_community_sets["openconfig-bgp-policy:ext-community-sets"]["openconfig-bgp-policy:ext-community-set"].append(new_ext_community_set)
            common.get_index_or_default(ext_community_list_after, ext_community_index, {})["name"] = None
            common.get_index_or_default(ext_community_list_after, ext_community_index, {})["set"] = None
    
    for community_list_item in ext_community_list_after:
        if "name" in community_list_item and community_list_item["name"]:
            updated_community_list.append(community_list_item)
    
    if len(updated_community_list) > 0:
        ext_community_list_after[type] = updated_community_list
    elif type in ext_community_list_after:
        del ext_community_list_after[type]



def process_policy_definitions(config_before, config_after):
     
    policy = {
            "openconfig-routing-policy:policy-definitions": {
                "openconfig-routing-policy:policy-definition": []
            }
        }   

    for route_policy_index, route_policy in enumerate(config_before.get("tailf-ned-cisco-ios-xr:route-policy", [])):
        
        current_route_policy = format_route_policy(route_policy.get("value"))
        if current_route_policy is None:
            continue
        if current_route_policy.get("match") and current_route_policy.get("action"):
            statement = {
                    "openconfig-routing-policy:name": route_policy.get('name'),
                    "openconfig-routing-policy:config": {
                        "openconfig-routing-policy:name": route_policy.get('name')
                    },
                    "openconfig-routing-policy:statements": {
                        "openconfig-routing-policy:statement": [
                        {
                            "openconfig-routing-policy:name": current_route_policy.get("match"),
                            "openconfig-routing-policy:config": {
                                "openconfig-routing-policy:name": current_route_policy.get("match")
                            },
                            "openconfig-routing-policy:actions": {
                                "openconfig-routing-policy:config": {
                                    "openconfig-routing-policy:policy-result": current_route_policy.get("action")
                                }
                            }
                        }
                    ]
                }
            }
        
            policy["openconfig-routing-policy:policy-definitions"]["openconfig-routing-policy:policy-definition"].append(statement)
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["name"] = None
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["value"] = None
        
        elif current_route_policy.get("match") and current_route_policy.get("set") == "local-preference":
            statement = {
                "openconfig-routing-policy:name": route_policy.get('name'),
                    "openconfig-routing-policy:config": {
                        "openconfig-routing-policy:name": route_policy.get('name')
                    },
                    "openconfig-routing-policy:statements": {
                        "openconfig-routing-policy:statement": [
                        {
                            "openconfig-routing-policy:name": current_route_policy.get("match"),
                            "openconfig-routing-policy:config": {
                                "openconfig-routing-policy:name": current_route_policy.get("match")
                            },
                            "openconfig-routing-policy:actions": {
                                "openconfig-routing-policy:config": {
                                    "openconfig-routing-policy:policy-result": "ACCEPT_ROUTE"
                                },
                                "openconfig-bgp-policy:bgp-actions": {
                                    "openconfig-bgp-policy:config": {
                                        "openconfig-bgp-policy:set-local-pref": current_route_policy.get("set_value")
                                    }
                                }
                            }
                        }
                    ]
                }
            }
            policy["openconfig-routing-policy:policy-definitions"]["openconfig-routing-policy:policy-definition"].append(statement)
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["name"] = None
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["value"] = None

        elif current_route_policy.get("match") and current_route_policy.get("set") == "community":
            statement = {
                "openconfig-routing-policy:name": route_policy.get('name'),
                    "openconfig-routing-policy:config": {
                        "openconfig-routing-policy:name": route_policy.get('name')
                    },
                    "openconfig-routing-policy:statements": {
                        "openconfig-routing-policy:statement": [
                        {
                            "openconfig-routing-policy:name": current_route_policy.get("match"),
                            "openconfig-routing-policy:config": {
                                "openconfig-routing-policy:name": current_route_policy.get("match")
                            },
                            "openconfig-routing-policy:actions": {
                                "openconfig-routing-policy:config": {
                                    "openconfig-routing-policy:policy-result": "ACCEPT_ROUTE"
                                },
                                "openconfig-bgp-policy:bgp-actions": {
                                    "openconfig-bgp-policy:config": {
                                        "openconfig-bgp-policy:set-community": {
                                            "openconfig-bgp-policy:config": {
                                                "openconfig-bgp-policy:method": "INLINE",
                                                "openconfig-bgp-policy:options": "REPLACE"
                                            },
                                            "openconfig-bgp-policy:inline": {
                                                "openconfig-bgp-policy:config": {
                                                    "openconfig-bgp-policy:communities": current_route_policy.get("set_value")
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            }
            policy["openconfig-routing-policy:policy-definitions"]["openconfig-routing-policy:policy-definition"].append(statement)
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["name"] = None
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["value"] = None

        elif current_route_policy.get("match") and current_route_policy.get("set") == "med":
            statement = {
                "openconfig-routing-policy:name": route_policy.get('name'),
                    "openconfig-routing-policy:config": {
                        "openconfig-routing-policy:name": route_policy.get('name')
                    },
                    "openconfig-routing-policy:statements": {
                        "openconfig-routing-policy:statement": [
                        {
                            "openconfig-routing-policy:name": current_route_policy.get("match"),
                            "openconfig-routing-policy:config": {
                                "openconfig-routing-policy:name": current_route_policy.get("match")
                            },
                            "openconfig-routing-policy:actions": {
                                "openconfig-routing-policy:config": {
                                    "openconfig-routing-policy:policy-result": "ACCEPT_ROUTE"
                                },
                                "openconfig-bgp-policy:bgp-actions": {
                                    "openconfig-bgp-policy:config": {
                                        "openconfig-bgp-policy:set-med": current_route_policy.get("set_value")
                                    }
                                }
                            }
                        }
                    ]
                }
            }
            policy["openconfig-routing-policy:policy-definitions"]["openconfig-routing-policy:policy-definition"].append(statement)
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["name"] = None
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["value"] = None

        if not current_route_policy.get("match") and current_route_policy.get("set") == "local-preference":
            statement = {
                "openconfig-routing-policy:name": route_policy.get('name'),
                    "openconfig-routing-policy:config": {
                        "openconfig-routing-policy:name": route_policy.get('name')
                    },
                    "openconfig-routing-policy:statements": {
                        "openconfig-routing-policy:statement": [
                        {
                            "openconfig-bgp-policy:bgp-actions": {
                                "openconfig-bgp-policy:config": {
                                    "openconfig-bgp-policy:set-local-pref": current_route_policy.get("set_value")
                                }
                            }
                        }
                    ]
                }
            }
            policy["openconfig-routing-policy:policy-definitions"]["openconfig-routing-policy:policy-definition"].append(statement)
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["name"] = None
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["value"] = None

        elif not current_route_policy.get("match") and current_route_policy.get("set") == "community":
            statement = {
                "openconfig-routing-policy:name": route_policy.get('name'),
                    "openconfig-routing-policy:config": {
                        "openconfig-routing-policy:name": route_policy.get('name')
                    },
                    "openconfig-routing-policy:statements": {
                        "openconfig-routing-policy:statement": [
                        {
                            "openconfig-bgp-policy:bgp-actions": {
                                "openconfig-bgp-policy:config": {
                                    "openconfig-bgp-policy:set-community": {
                                        "openconfig-bgp-policy:config": {
                                            "openconfig-bgp-policy:method": "INLINE",
                                            "openconfig-bgp-policy:options": "REPLACE"
                                        },
                                        "openconfig-bgp-policy:inline": {
                                            "openconfig-bgp-policy:config": {
                                                "openconfig-bgp-policy:communities": current_route_policy.get("set_value")
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            }
            policy["openconfig-routing-policy:policy-definitions"]["openconfig-routing-policy:policy-definition"].append(statement)
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["name"] = None
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["value"] = None

        elif not current_route_policy.get("match") and current_route_policy.get("set") == "med":
            statement = {
                "openconfig-routing-policy:name": route_policy.get('name'),
                    "openconfig-routing-policy:config": {
                        "openconfig-routing-policy:name": route_policy.get('name')
                    },
                    "openconfig-routing-policy:statements": {
                        "openconfig-routing-policy:statement": [
                        {
                            "openconfig-bgp-policy:bgp-actions": {
                                "openconfig-bgp-policy:config": {
                                    "openconfig-bgp-policy:set-med": current_route_policy.get("set_value")
                                }
                            }
                        }
                    ]
                }
            }
            policy["openconfig-routing-policy:policy-definitions"]["openconfig-routing-policy:policy-definition"].append(statement)
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["name"] = None
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["value"] = None

        elif not current_route_policy.get("match") and current_route_policy.get("prepend"):
            statement = {
                "openconfig-routing-policy:name": route_policy.get('name'),
                    "openconfig-routing-policy:config": {
                        "openconfig-routing-policy:name": route_policy.get('name')
                    },
                    "openconfig-routing-policy:statements": {
                        "openconfig-routing-policy:statement": [
                        {
                            "openconfig-bgp-policy:bgp-actions": {
                                "openconfig-bgp-policy:config": {
                                    "openconfig-bgp-policy:set-as-path-prepend": {
                                        "openconfig-bgp-policy:config": {
                                            "openconfig-bgp-policy:asn": current_route_policy.get("prepend")
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            }
            policy["openconfig-routing-policy:policy-definitions"]["openconfig-routing-policy:policy-definition"].append(statement)
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["name"] = None
            config_after["tailf-ned-cisco-ios-xr:route-policy"][route_policy_index]["value"] = None
        
    openconfig_routing_policies.update(policy)


def format_route_policy(old_route_policy):

    # Define the regular expressions to match the required sections
    specific_prefix_regex = re.compile(r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+)\)')
    match_prefix_list_regex = re.compile(r'^  if destination in ([^ ]+)')
    action_regex = re.compile(r'then\r\r\n    ([^ ]+)')
    starts_with_set_regex = re.compile(r'^  set\s([^ ]+)\s([^ ]+)')
    starts_with_prepend_regex = re.compile(r'^  prepend as-path ((?:\d+ *)+)')
    action_set_regex = re.compile(r'    set\s([^ ]+)\s([^ ]+)')
    action_prepend_regex = re.compile(r'    prepend as-path ((?:\d+ *)+)')

    # Find the matches
    specific_prefix = specific_prefix_regex.search(old_route_policy)
    match_prefix_list = match_prefix_list_regex.search(old_route_policy)
    action = action_regex.search(old_route_policy)
    starts_with_set_commands = starts_with_set_regex.search(old_route_policy)
    starts_with_prepend = starts_with_prepend_regex.search(old_route_policy)
    action_set_commands = action_set_regex.search(old_route_policy)
    action_prepend = action_prepend_regex.search(old_route_policy)    

    # Check unsupported actions
    # Check if the route policy contains a specific prefix
    if specific_prefix or "elseif" in old_route_policy:
        print(f"""found: {old_route_policy}
              this prefix is unsupported at this time.
              Skipping...""")
        return None
    
    # Check if the route policy contains a match and action
    if match_prefix_list and action.group(1):
        # Extract the matched values
        prefix_list = match_prefix_list.group(1) if match_prefix_list else None
        action = "ACCEPT_ROUTE" if action.group(1) == "pass" else action.group(1)
        # Construct the new dictionary
        result = {
            'match': prefix_list,
            'action': "ACCEPT_ROUTE"
        }
        return result
    
    if match_prefix_list and action_set_commands: 
        # Extract the matched values
        prefix_list = match_prefix_list.group(1) if match_prefix_list else None
        set_commands = action_set_commands.group(1) if action_set_commands else None
        set_value = action_set_commands.group(2) if action_set_commands else None

        # Construct the new dictionary
        result = {
            'match': prefix_list,
            'set': set_commands,
            'set_value': set_value
        }
        return result
    
    elif match_prefix_list and action_prepend:
        # Extract the matched values
        prefix_list = match_prefix_list.group(1) if match_prefix_list else None
        prepend = action_prepend.group(2) if action_prepend else None

        # Construct the new dictionary
        result = {
            'match': prefix_list,
            'prepend': prepend
        }
        return result
    
    elif starts_with_set_commands:
        # Extract the matched values
        set_commands = starts_with_set_commands.group(1) if starts_with_set_commands else None
        set_value = starts_with_set_commands.group(2) if starts_with_set_commands else None

        # Construct the new dictionary
        result = {
            'set': set_commands.strip("\r\r\n"),
            'set_value': set_value.strip("\r\r\n")
        }
        return result
    elif starts_with_prepend:
        # Extract the matched values
        prepend = starts_with_prepend.group(1)

        # Construct the new dictionary
        result = {
            'prepend': prepend
        }
        return result
    

    



def main(before: dict, leftover: dict, translation_notes: list = []) -> dict:
    """
    Translates NSO Device configurations to MDD OpenConfig configurations.

    Requires environment variables:
    NSO_HOST: str
    NSO_USERNAME: str
    NSO_PASSWORD: str
    NSO_DEVICE: str
    TEST - If True, sends generated OC configuration to NSO Server: str

    :param before: Original NSO Device configuration: dict
    :param leftover: NSO Device configuration minus configs replaced with MDD OC: dict
    :return: MDD Openconfig Network Instances configuration: dict
    """

    xr_routing_policy(before, leftover)
    translation_notes += routing_policy_notes

    return openconfig_routing_policies

if __name__ == "__main__":
    sys.path.append("../../")
    sys.path.append("../../../")

    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xr import common_xr
        from package_nso_to_oc import common
    else:
        import common_xr
        import common

    (config_before_dict, config_leftover_dict, interface_ip_dict) = common_xr.init_xr_configs()
    main(config_before_dict, config_leftover_dict)
    config_name = "_routing_policies"
    config_remaining_name = "_remaining_routing_policies"
    oc_name = "_openconfig_routing_policies"
    common.print_and_test_configs(
        "xr1", config_before_dict, config_leftover_dict, openconfig_routing_policies,
        config_name, config_remaining_name, oc_name, routing_policy_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xr import common_xr
        from package_nso_to_oc import common
    else:
        from xr import common_xr
        import common
