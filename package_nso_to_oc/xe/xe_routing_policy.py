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
# OC has an additional "NOPEER" BGP community member, which is not support in XE.
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

def xe_routing_policy(config_before, config_after):
    process_prefix_sets(config_before, config_after)
    process_as_path_sets(config_before, config_after)
    process_community_sets(config_before, config_after)
    process_ext_community_sets(config_before, config_after)
    process_policy_definitions(config_before, config_after)

def process_prefix_sets(config_before, config_after):
    prefix_sets = {"openconfig-routing-policy:prefix-sets": {"openconfig-routing-policy:prefix-set": []}}
    xe_prefixes = config_before.get("tailf-ned-cisco-ios:ip", {}).get("prefix-list", {}).get("prefixes", [])
    xe_prefixes_after = config_after.get("tailf-ned-cisco-ios:ip", {}).get("prefix-list", {}).get("prefixes", [])
    prefixes_list = []

    for prefix_index, prefix in enumerate(xe_prefixes):
        new_prefix_set = {
            "openconfig-routing-policy:name": prefix.get("name"),
            "openconfig-routing-policy:config": {
                "openconfig-routing-policy:name": prefix.get("name"),
                "openconfig-routing-policy:mode": "IPV4"
            },
            "openconfig-routing-policy:prefixes": {"openconfig-routing-policy:prefix": []}
        }
        prefixes = new_prefix_set["openconfig-routing-policy:prefixes"]["openconfig-routing-policy:prefix"]
        seq_list_after = common.get_index_or_default(xe_prefixes_after, prefix_index, {}).get("seq", [])

        for seq_index, seq in enumerate(prefix.get("seq", [])):
            if "deny" in seq:
                masklength = "exact" if not "le" in seq["deny"] else f'{seq["deny"].get("ge", 0)}..{seq["deny"]["le"]}'
                new_prefix = {
                    "openconfig-routing-policy:ip-prefix": seq["deny"].get("ip"),
                    "openconfig-routing-policy:masklength-range": masklength,
                    "openconfig-routing-policy:config": {
                        "openconfig-routing-policy:ip-prefix": seq["deny"].get("ip"),
                        "openconfig-routing-policy:masklength-range": masklength,
                        "openconfig-routing-policy-ext:seq": seq["no"],
                        "openconfig-routing-policy-ext:policy_action": 'DENY_ROUTE'
                    }
                }
            elif "permit" in seq:
                masklength = "exact" if not "le" in seq["permit"] else f'{seq["permit"].get("ge", 0)}..{seq["permit"]["le"]}'
                new_prefix = {
                    "openconfig-routing-policy:ip-prefix": seq["permit"].get("ip"),
                    "openconfig-routing-policy:masklength-range": masklength,
                    "openconfig-routing-policy:config": {
                        "openconfig-routing-policy:ip-prefix": seq["permit"].get("ip"),
                        "openconfig-routing-policy:masklength-range": masklength,
                        "openconfig-routing-policy-ext:seq": seq["no"],
                        "openconfig-routing-policy-ext:policy_action": 'PERMIT_ROUTE'
                    }
                }

            prefixes.append(new_prefix)

            # Ensure the value we're nullifying does exist
            if common.get_index_or_default(seq_list_after, seq_index, None):
                seq_list_after[seq_index] = None

        prefix_sets["openconfig-routing-policy:prefix-sets"]["openconfig-routing-policy:prefix-set"].append(new_prefix_set)
        common.get_index_or_default(xe_prefixes_after, prefix_index, {})["name"] = None

    for prefix_item in config_after.get("tailf-ned-cisco-ios:ip", {}).get("prefix-list", {}).get("prefixes", []):
        if "name" in prefix_item and prefix_item["name"]:
            prefixes_list.append(prefix_item)

    if len(prefixes_list) > 0:
        config_after["tailf-ned-cisco-ios:ip"]["prefix-list"]["prefixes"] = prefixes_list
    elif "prefixes" in config_after.get("tailf-ned-cisco-ios:ip", {}).get("prefix-list", {}):
        del config_after["tailf-ned-cisco-ios:ip"]["prefix-list"]["prefixes"]

    openconfig_routing_policies["openconfig-routing-policy:routing-policy"]["openconfig-routing-policy:defined-sets"].update(prefix_sets)


def process_as_path_sets(config_before, config_after):
    as_path_sets = {"openconfig-bgp-policy:as-path-sets": {"openconfig-bgp-policy:as-path-set": []}}
    access_list = config_before.get("tailf-ned-cisco-ios:ip", {}).get("as-path", {}).get("access-list", [])
    access_list_after = config_after.get("tailf-ned-cisco-ios:ip", {}).get("as-path", {}).get("access-list", [])
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
    
    for access_list_item in config_after.get("tailf-ned-cisco-ios:ip", {}).get("as-path", {}).get("access-list", []):
        if "name" in access_list_item and access_list_item["name"]:
            updated_access_list.append(access_list_item)
    
    if len(updated_access_list) > 0:
        config_after["tailf-ned-cisco-ios:ip"]["as-path"]["access-list"] = updated_access_list
    elif "access-list" in config_after.get("tailf-ned-cisco-ios:ip", {}).get("as-path", {}):
        del config_after["tailf-ned-cisco-ios:ip"]["as-path"]["access-list"]

    openconfig_routing_policies["openconfig-routing-policy:routing-policy"]["openconfig-routing-policy:defined-sets"]["openconfig-bgp-policy:bgp-defined-sets"].update(as_path_sets)

def process_community_sets(config_before, config_after):
    community_sets = {"openconfig-bgp-policy:community-sets": {"openconfig-bgp-policy:community-set": []}}
    community_list = config_before.get("tailf-ned-cisco-ios:ip", {}).get("community-list", {})
    community_list_after = config_after.get("tailf-ned-cisco-ios:ip", {}).get("community-list", {})
    process_community_members(community_sets, "number", community_list, community_list_after)
    process_community_members(community_sets, "standard", community_list, community_list_after)
    process_community_members(community_sets, "expanded", community_list, community_list_after)
    openconfig_routing_policies["openconfig-routing-policy:routing-policy"]["openconfig-routing-policy:defined-sets"]["openconfig-bgp-policy:bgp-defined-sets"].update(community_sets)

def process_community_members(community_sets, type, community_list, community_list_after):
    all_processed = True
    updated_community_list = []
    name_or_num_key = "no" if type == "number" else "name"

    for community_index, community in enumerate(community_list.get(type, [])):
        new_community_set = {
            "openconfig-bgp-policy:community-set-name": community.get(name_or_num_key),
            "openconfig-bgp-policy:config": {
                "openconfig-bgp-policy:community-set-name": community.get(name_or_num_key),
                "openconfig-bgp-policy:match-set-options": "ANY", # IOS only supports ANY
                "openconfig-bgp-policy:community-member": []
            }
        }
        members = new_community_set["openconfig-bgp-policy:config"]["openconfig-bgp-policy:community-member"]
        entry_after = common.get_index_or_default(community_list_after.get(type, []), community_index, {}).get("entry", [])

        for entry_index, entry in enumerate(community.get("entry", [])):
            if not "expr" in entry:
                continue
            if entry["expr"].startswith("deny"):
                all_processed = False
                routing_policy_notes.append(
f"""
Community Name: {community.get(name_or_num_key)}
Community Type: {type}
Entry: {entry["expr"]}
This entry contains a deny operation, which is not supported in OpenConfig. Translation, of the entire list, to OC will be skipped.
""")
                continue

            member = entry["expr"][entry["expr"].find(' ') + 1:]
            members.append(well_known_members.get(member, member))

            # Ensure the value we're nullifying does exist
            if common.get_index_or_default(entry_after, entry_index, None):
                entry_after[entry_index] = None

        if all_processed:
            community_sets["openconfig-bgp-policy:community-sets"]["openconfig-bgp-policy:community-set"].append(new_community_set)
            common.get_index_or_default(community_list_after.get(type, []), community_index, {})[name_or_num_key] = None
    
    for community_list_item in community_list_after.get(type, []):
        if name_or_num_key in community_list_item and community_list_item[name_or_num_key]:
            updated_community_list.append(community_list_item)
    
    if len(updated_community_list) > 0:
        community_list_after[type] = updated_community_list
    elif type in community_list_after:
        del community_list_after[type]

def process_ext_community_sets(config_before, config_after):
    ext_community_sets = {"openconfig-bgp-policy:ext-community-sets": {"openconfig-bgp-policy:ext-community-set": []}}
    ext_community_list = config_before.get("tailf-ned-cisco-ios:ip", {}).get("extcommunity-list", {})
    ext_community_list_after = config_after.get("tailf-ned-cisco-ios:ip", {}).get("extcommunity-list", {})
    process_ext_community_members(ext_community_sets, "number", ext_community_list, ext_community_list_after)
    process_ext_community_members(ext_community_sets, "standard", ext_community_list, ext_community_list_after)
    process_ext_community_members(ext_community_sets, "expanded", ext_community_list, ext_community_list_after)
    openconfig_routing_policies["openconfig-routing-policy:routing-policy"]["openconfig-routing-policy:defined-sets"]["openconfig-bgp-policy:bgp-defined-sets"].update(ext_community_sets)

def process_ext_community_members(ext_community_sets, type, ext_community_list, ext_community_list_after):
    all_processed = True
    updated_ext_community_list = []
    name_or_num_key = "no" if type == "number" else "name"

    for ext_community_index, ext_community in enumerate(ext_community_list.get(type, {"no-mode-list": []}).get("no-mode-list", [])):
        ext_new_community_set = {
            "openconfig-bgp-policy:ext-community-set-name": ext_community.get(name_or_num_key),
            "openconfig-bgp-policy:config": {
                "openconfig-bgp-policy:ext-community-set-name": ext_community.get(name_or_num_key),
                "openconfig-bgp-policy:ext-community-member": []
            }
        }
        ext_members = ext_new_community_set["openconfig-bgp-policy:config"]["openconfig-bgp-policy:ext-community-member"]
        entry_after = common.get_index_or_default(ext_community_list_after.get(type, {"no-mode-list": []}).get("no-mode-list", []), ext_community_index, {}).get("entry", [])

        for entry_index, entry in enumerate(ext_community.get("entry", [])):
            if not "expr" in entry:
                continue
            if entry["expr"].startswith("deny"):
                all_processed = False
                routing_policy_notes.append(
f"""
Ext Community Name: {ext_community.get(name_or_num_key)}
Ext Community Type: {type}
Ext Entry: {entry["expr"]}
This ext entry contains a deny operation, which is not supported in OpenConfig. Translation, of the entire list, to OC will be skipped.
""")
                continue

            member = entry["expr"][entry["expr"].find(' rt ') + 4:]
            ext_members.append(well_known_members.get(member, member))

            # Ensure the value we're nullifying does exist
            if common.get_index_or_default(entry_after, entry_index, None):
                entry_after[entry_index] = None

        if all_processed:
            ext_community_sets["openconfig-bgp-policy:ext-community-sets"]["openconfig-bgp-policy:ext-community-set"].append(ext_new_community_set)
            common.get_index_or_default(ext_community_list_after.get(type, {"no-mode-list": []}).get("no-mode-list", []), ext_community_index, {})[name_or_num_key] = None
    
    for community_list_item in ext_community_list_after.get(type, {"no-mode-list": []}).get("no-mode-list", []):
        if name_or_num_key in community_list_item and community_list_item[name_or_num_key]:
            updated_ext_community_list.append(community_list_item)
    
    if len(updated_ext_community_list) > 0:
        ext_community_list_after[type]["no-mode-list"] = updated_ext_community_list
    elif type in ext_community_list_after and "no-mode-list" in ext_community_list_after[type]:
        del ext_community_list_after[type]["no-mode-list"]

def process_policy_definitions(config_before, config_after):
    prev_policy_name = ""
    updated_route_map = []

    for route_map_index, route_map in enumerate(config_before.get("tailf-ned-cisco-ios:route-map", [])):
        if (prev_policy_name != route_map.get("name")):
            prev_policy_name = route_map.get("name")
            policy_def = {
                "openconfig-routing-policy:name": route_map.get("name"),
                "openconfig-routing-policy:config": {"openconfig-routing-policy:name": route_map.get("name")},
                "openconfig-routing-policy:statements": {"openconfig-routing-policy:statement": []}
            }
            openconfig_routing_policies["openconfig-routing-policy:routing-policy"]["openconfig-routing-policy:policy-definitions"][
                "openconfig-routing-policy:policy-definition"].append(policy_def)

        statement = {
            "openconfig-routing-policy:name": route_map["sequence"],
            "openconfig-routing-policy:config": {"openconfig-routing-policy:name": route_map["sequence"]},
            "openconfig-routing-policy:actions": {
                "openconfig-routing-policy:config": {"openconfig-routing-policy:policy-result": policy_results[route_map["operation"]]},
                "openconfig-bgp-policy:bgp-actions":{
                    "openconfig-bgp-policy:config": {},
                    "openconfig-bgp-policy:set-community": {},
                    "openconfig-bgp-policy:set-ext-community": {}
                }
            },
            "openconfig-routing-policy:conditions": {
                "openconfig-bgp-policy:bgp-conditions": {"openconfig-bgp-policy:config": {}}
            }
        }
        policy_def["openconfig-routing-policy:statements"]["openconfig-routing-policy:statement"].append(statement)

        if "match" in route_map:
            process_match(route_map["match"], statement["openconfig-routing-policy:conditions"])
        if "set" in route_map:
            process_set(route_map["set"], statement["openconfig-routing-policy:actions"])
        if common.get_index_or_default(config_after.get("tailf-ned-cisco-ios:route-map", []), route_map_index, None):
            config_after["tailf-ned-cisco-ios:route-map"][route_map_index] = None
    
    for route_map_item in config_after.get("tailf-ned-cisco-ios:route-map", []):
        if route_map_item:
            updated_route_map.append(route_map_item)
    
    if len(updated_route_map) > 0:
        config_after["tailf-ned-cisco-ios:route-map"] = updated_route_map
    elif "tailf-ned-cisco-ios:route-map" in config_after:
        del config_after["tailf-ned-cisco-ios:route-map"]

def process_match(route_map_match, conditions):
    if len(route_map_match.get("ip", {}).get("address", {}).get("prefix-list", [])) > 0:
        conditions.update({
            "openconfig-routing-policy:match-prefix-set": {
                "openconfig-routing-policy:config": {
                    "openconfig-routing-policy:prefix-set": route_map_match["ip"]["address"]["prefix-list"][0],
                    "openconfig-routing-policy:match-set-options": "ANY"
                }
            }
        })
    if len(route_map_match.get("tag", [])) == 1:
        conditions.update({
            "openconfig-routing-policy:match-tag-set": {
                "openconfig-routing-policy:config": {
                    "openconfig-routing-policy:tag-set": str(route_map_match["tag"][0]),
                    "openconfig-routing-policy:match-set-options": "ANY"
                }
            }
        })
        openconfig_routing_policies["openconfig-routing-policy:routing-policy"]["openconfig-routing-policy:defined-sets"][
            "openconfig-routing-policy:tag-sets"]["openconfig-routing-policy:tag-set"].append({
                "openconfig-routing-policy:name": str(route_map_match["tag"][0]),
                "openconfig-routing-policy:config": {
                    "openconfig-routing-policy:name": str(route_map_match["tag"][0]),
                    "openconfig-routing-policy:tag-value": [route_map_match["tag"][0]]
                }
            })
    if "as-path" in route_map_match:
        conditions["openconfig-bgp-policy:bgp-conditions"].update({
            "openconfig-bgp-policy:match-as-path-set": {
                "openconfig-bgp-policy:config": {
                    "openconfig-bgp-policy:as-path-set": route_map_match["as-path"][0],
                    "openconfig-bgp-policy:match-set-options": "ANY"
                }
            }
        })
    if "community" in route_map_match:
        conditions["openconfig-bgp-policy:bgp-conditions"]["openconfig-bgp-policy:config"].update({
            "openconfig-bgp-policy:community-set": route_map_match["community"][0]
        })
    if "extcommunity" in route_map_match:
        conditions["openconfig-bgp-policy:bgp-conditions"]["openconfig-bgp-policy:config"].update({
            "openconfig-bgp-policy:ext-community-set": route_map_match["extcommunity"][0]
        })
    if len(route_map_match.get("ip", {}).get("address", {}).get("access-list", [])) > 0:
        conditions.update({
            "openconfig-routing-policy-ext:match-acl-ipv4-set": {
                "openconfig-routing-policy-ext:config": {
                    "openconfig-routing-policy-ext:acl-set": route_map_match["ip"]["address"]["access-list"][0]
                }
            }
        })


def format_well_known_communities(community_number):
    for i in well_known_members:
        if i in community_number:
            index = community_number.index(i)
            community_number[index] = well_known_members.get(i, i)


def process_set(route_map_set, actions):
    if "tag" in route_map_set:
        actions.update({
            "openconfig-routing-policy:set-tag": {
                "openconfig-routing-policy:config": {
                    "openconfig-routing-policy:mode": "INLINE"
                },
                "openconfig-routing-policy:inline": {
                    "openconfig-routing-policy:config": {
                        "openconfig-routing-policy:tag": [str(route_map_set["tag"])]
                    }
                }
            }
        })
    if route_map_set.get("origin", {}).get("origin-value", None) and route_map_set["origin"]["origin-value"] != "egp":
        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:config"].update({
            "openconfig-bgp-policy:set-route-origin": route_map_set["origin"]["origin-value"].upper()
        })
    if route_map_set.get("local-preference", {}).get("value", None):
        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:config"].update({
            "openconfig-bgp-policy:set-local-pref": str(route_map_set["local-preference"]["value"])
        })
    if len(route_map_set.get("ip", {}).get("next-hop", {}).get("self", [])) > 0:
        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:config"].update({
            "openconfig-bgp-policy:set-next-hop": "SELF"
        })
    if len(route_map_set.get("ip", {}).get("next-hop", {}).get("address", [])) > 0:
        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:config"].update({
            "openconfig-bgp-policy:set-next-hop": route_map_set["ip"]["next-hop"]["address"]
        })
    if "metric" in route_map_set:
        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:config"].update({
            "openconfig-bgp-policy:set-med": route_map_set["metric"]
        })
    if "weight" in route_map_set:
        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:config"].update({
            "openconfig-routing-policy-ext:set-weight": route_map_set["weight"]
        })
    if route_map_set.get("as-path", {}).get("prepend", {}).get("as-list", None):
        as_list = route_map_set["as-path"]["prepend"]["as-list"].split(" ")
        actions["openconfig-bgp-policy:bgp-actions"].update({
            "openconfig-bgp-policy:set-as-path-prepend": {"openconfig-bgp-policy:config": {}}
        })
        path_prepend = actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:set-as-path-prepend"][
            "openconfig-bgp-policy:config"]
        path_prepend["openconfig-bgp-policy:asn"] = as_list[0]

        if len(as_list) > 1:
            path_prepend["openconfig-bgp-policy:repeat-n"] = str(len(as_list))
    if len(route_map_set.get("community", {}).get("community-number", [])) > 0:
        community_number = route_map_set["community"]["community-number"]
        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:set-community"].update({
            "openconfig-bgp-policy:config": {
                "openconfig-bgp-policy:method": "INLINE"
            }
        })

        if "additive" in route_map_set["community"]["community-number"]:
            actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:set-community"]["openconfig-bgp-policy:config"][
                "openconfig-bgp-policy:options"] = "ADD"
            community_number.remove("additive")
        else:
            actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:set-community"]["openconfig-bgp-policy:config"][
                "openconfig-bgp-policy:options"] = "REPLACE"

        format_well_known_communities(community_number)
        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:set-community"].update({
            "openconfig-bgp-policy:inline": {
                "openconfig-bgp-policy:config": {
                    "openconfig-bgp-policy:communities": community_number
                }
            }
        })
    if route_map_set.get("comm-list", {}).get("name", None) and len(route_map_set.get("comm-list", {}).get("delete", [])) > 0:
        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:set-community"].update({
            "openconfig-bgp-policy:config": {
                "openconfig-bgp-policy:method": "REFERENCE",
                "openconfig-bgp-policy:options": "REMOVE"
            },
            "openconfig-bgp-policy:reference": {
                "openconfig-bgp-policy:config": {
                    "openconfig-bgp-policy:community-set-ref": route_map_set["comm-list"]["name"]
                }
            }
        })
    if len(route_map_set.get("extcommunity", {}).get("rt", [])) > 0:
        rt_number = route_map_set["extcommunity"]["rt"]
        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:set-ext-community"].update({
            "openconfig-bgp-policy:config": {
                "openconfig-bgp-policy:method": "INLINE"
            }
        })

        if "additive" in route_map_set["extcommunity"]["rt"]:
            actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:set-ext-community"]["openconfig-bgp-policy:config"][
                "openconfig-bgp-policy:options"] = "ADD"
            rt_number.remove("additive")
        else:
            actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:set-ext-community"]["openconfig-bgp-policy:config"][
                "openconfig-bgp-policy:options"] = "REPLACE"

        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:set-ext-community"].update({
            "openconfig-bgp-policy:inline": {
                "openconfig-bgp-policy:config": {
                    "openconfig-bgp-policy:communities": rt_number
                }
            }
        })
    if route_map_set.get("extcomm-list", {}).get("name", None) and len(route_map_set.get("extcomm-list", {}).get("delete", [])) > 0:
        actions["openconfig-bgp-policy:bgp-actions"]["openconfig-bgp-policy:set-ext-community"].update({
            "openconfig-bgp-policy:config": {
                "openconfig-bgp-policy:method": "REFERENCE",
                "openconfig-bgp-policy:options": "REMOVE"
            },
            "openconfig-bgp-policy:reference": {
                "openconfig-bgp-policy:config": {
                    "openconfig-bgp-policy:ext-community-set-ref": route_map_set["extcomm-list"]["name"]
                }
            }
        })

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

    xe_routing_policy(before, leftover)
    translation_notes += routing_policy_notes

    return openconfig_routing_policies

if __name__ == "__main__":
    sys.path.append("../../")
    sys.path.append("../../../")

    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc import common
    else:
        import common_xe
        import common

    (config_before_dict, config_leftover_dict, interface_ip_dict) = common_xe.init_xe_configs()
    main(config_before_dict, config_leftover_dict)
    config_name = "_routing_policies"
    config_remaining_name = "_remaining_routing_policies"
    oc_name = "_openconfig_routing_policies"
    common.print_and_test_configs(
        "xe1", config_before_dict, config_leftover_dict, openconfig_routing_policies,
        config_name, config_remaining_name, oc_name, routing_policy_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc import common
    else:
        from xe import common_xe
        import common
