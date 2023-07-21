#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_network_instances.json,
save the NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_ned_configuration_remaining_network_instances.json, and save the MDD OpenConfig configuration to a file
named {nso_device}_openconfig_acls.json.

The script requires the following environment variables:
NSO_URL - URL for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation
TEST - True or False. True enables sending the OpenConfig to the NSO server after generation
"""

import sys
from importlib.util import find_spec
from ipaddress import IPv4Network
import os
import socket
import re

ACL_USE_EXISTING_SEQ = os.environ.get("ACL_USE_EXISTING_SEQ", "False")

acls_notes = []
openconfig_acls = {
    "openconfig-acl:acl": {
        "openconfig-acl:acl-sets": {
            "openconfig-acl:acl-set": []
        },
        "openconfig-acl:interfaces": {
            "openconfig-acl:interface": []
        }
    }
}
protocols_oc_to_xe = {
    "icmp": "IP_ICMP",
    "igmp": "IP_IGMP",
    "ipnip": "IP_IN_IP",
    "tcp": "IP_TCP",
    "udp": "IP_UDP",
    "gre": "IP_GRE",
    "ahp": "IP_AUTH",
    "esp": "IP_ESP",
    "pim": "IP_PIM"
}
icmp_names_to_types = {
    'administratively-prohibited': (3, 13),
    'alternate-address': (6, 0),
    'dod-host-prohibited': (3, 10),
    'dod-net-prohibited': (3, 9),
    'echo': (8, 0),
    'echo-reply': (0, 0),
    'general-parameter-problem': (12, 0),
    'host-redirect': (5, 1),
    'host-tos-redirect': (5, 3),
    'host-tos-unreachable': (3, 12),
    'host-unknown': (3, 7),
    'host-unreachable': (3, 1),
    'information-reply': (16, 0),
    'information-request': (15, 0),
    'mask-reply': (18, 0),
    'mask-request': (17, 0),
    'net-redirect': (5, 0),
    'net-tos-redirect': (5, 2),
    'net-tos-unreachable': (3, 11),
    'net-unreachable': (3, 0),
    'network-unknown': (3, 6),
    'no-room-for-option': (12, 2),
    'option-missing': (12, 1),
    'packet-too-big': (3, 4),
    'port-unreachable': (3, 3),
    'protocol-unreachable': (3, 2),
    'reassembly-timeout': (11, 1),
    'source-quench': (4, 0),
    'source-route-failed': (3, 5),
    'time-exceeded': (11, 0),
    'timestamp-reply': (14, 0),
    'timestamp-request': (13, 0),
    'unreachable': (3, 0)}
# OC has an additional forwarding action, "DROP", which also translates to "deny" in XE.
actions_xe_to_oc = {
    "permit": "ACCEPT",
    "deny": "REJECT",
    "remark": "REMARK"
}
port_operators = ["range", "eq", "lt", "gt", "neq"]
ACL_STD_TYPE = "ACL_IPV4_STANDARD"
ACL_EXT_TYPE = "ACL_IPV4"


def acls_note_add(note):
    acls_notes.append(note)


def xe_acls(config_before, config_after):
    oc_acl_set = openconfig_acls["openconfig-acl:acl"]["openconfig-acl:acl-sets"]["openconfig-acl:acl-set"]
    oc_acl_interface = openconfig_acls["openconfig-acl:acl"]["openconfig-acl:interfaces"]["openconfig-acl:interface"]
    access_list = config_before.get("tailf-ned-cisco-ios:ip", {}).get("access-list", {})
    access_list_after = config_after.get("tailf-ned-cisco-ios:ip", {}).get("access-list", {})
    numbered_access_list = config_before.get("tailf-ned-cisco-ios:access-list", {})
    numbered_access_list_after = config_after.get("tailf-ned-cisco-ios:access-list", {})
    interfaces_by_acl = get_interfaces_by_acl(config_before, config_after)
    acl_interfaces = {}
    # Numbered ACLs can be under tailf-ned-cisco-ios:ip/tailf-ned-cisco-ios:ip, tailf-ned-cisco-ios:access-list/access-list, or both
    # Store processes numbered ACLs in numbered_acls_processed
    numbered_acls_processed = []

    for std_index, std_acl in enumerate(access_list.get("standard", {}).get("std-named-acl", [])):
        standard_acl = StandardAcl(oc_acl_set, std_acl, access_list_after["standard"]["std-named-acl"][std_index])
        standard_acl.process_acl()
        process_interfaces(ACL_STD_TYPE, std_acl["name"], interfaces_by_acl, acl_interfaces)
        if str(std_acl["name"]).isdigit():
            numbered_acls_processed.append(int(std_acl["name"]))
    for ext_index, ext_acl in enumerate(access_list.get("extended", {}).get("ext-named-acl", [])):
        extended_acl = ExtendedAcl(oc_acl_set, ext_acl, access_list_after["extended"]["ext-named-acl"][ext_index])
        extended_acl.process_acl()
        process_interfaces(ACL_EXT_TYPE, ext_acl["name"], interfaces_by_acl, acl_interfaces)
        if str(ext_acl["name"]).isdigit():
            numbered_acls_processed.append(int(ext_acl["name"]))
    for numbered_index, numbered_acl in enumerate(numbered_access_list.get("access-list", [])):
        if numbered_acl["id"] not in numbered_acls_processed:
            if (1 <= numbered_acl["id"] <= 99) or (1300 <=  numbered_acl["id"] <= 1999):
                # process as standard
                standard_acl = NumberedStandardAcl(oc_acl_set, numbered_acl, numbered_access_list_after["access-list"][ numbered_index])
                standard_acl.process_acl()
            elif (100 <= numbered_acl["id"] <= 199) or (2000 <=  numbered_acl["id"] <= 2699):
                # process as extended
                extended_acl = NumberedExtendedAcl(oc_acl_set, numbered_acl, numbered_access_list_after["access-list"][ numbered_index])
                extended_acl.process_acl()
            else:
                acls_note_add(f"""
                    Access-list Number {numbered_acl["id"]} has not been implemented in MDD OpenConfig
                """)

    for interface in acl_interfaces.values():
        oc_acl_interface.append(interface)

    process_ntp(config_before, config_after)
    process_line(config_before, config_after)

    cleanup_empty_access_list(access_list_after.get("standard", {}), "std-named-acl")
    cleanup_empty_access_list(access_list_after.get("extended", {}), "ext-named-acl")
    cleanup_empty_access_list(numbered_access_list_after, "access-list")

def cleanup_empty_access_list(access_list_after, key):
    if len(access_list_after.get(key, [])) == 0:
        return

    updated_access_list = []

    for access_list_item in access_list_after[key]:
        if len(access_list_item) > 0:
            updated_access_list.append(access_list_item)
    
    if len(updated_access_list) > 0:
        access_list_after[key] = updated_access_list
    else:
        del access_list_after[key]

class BaseAcl:
    def __init__(self, oc_acl_set, xe_acl_set, xe_acl_set_after):
        self._oc_acl_set = oc_acl_set
        self._xe_acl_set = xe_acl_set
        self._xe_acl_set_after = xe_acl_set_after
        self._xe_acl_name = self._xe_acl_set.get("name")
        self._xe_acl_key = "name"
        self.acl_success = True
        self.ace_seq_begin = 10

    def process_acl(self):
        acl_set = {
            "openconfig-acl:name": str(self._xe_acl_name),
            "openconfig-acl:type": self._acl_type,
            "openconfig-acl:config": {
                "openconfig-acl:name": str(self._xe_acl_name),
                "openconfig-acl:type": self._acl_type,
                "openconfig-acl:description": str(self._xe_acl_name),  # XE doesn't seem to have a description.
            },
            "openconfig-acl:acl-entries": {
                "openconfig-acl:acl-entry": []
            }
        }
        self.acl_success = True
        updated_rule_list = []

        for rule_index, access_rule in enumerate(self._xe_acl_set.get(self._rule_list_key, [])):
            rule_success = self.__set_rule_parts(access_rule, acl_set)
            if rule_success:
                self._xe_acl_set_after[self._rule_list_key][rule_index] = None
            else:
                self.acl_success = False

        for rule_item in self._xe_acl_set_after.get(self._rule_list_key, []):
            if rule_item and len(rule_item) > 0:
                updated_rule_list.append(rule_item)
        
        if len(updated_rule_list) > 0:
            self._xe_acl_set_after[self._rule_list_key] = updated_rule_list
        elif self._rule_list_key in self._xe_acl_set_after:
            del self._xe_acl_set_after[self._rule_list_key]

        # We only delete if all entries processed successfully.
        # We only add the ACL to OpenConfig if all entries processed successfully.
        if self.acl_success:
            self._oc_acl_set.append(acl_set)
            del self._xe_acl_set_after[self._xe_acl_key]

    def __set_rule_parts(self, access_rule, acl_set):
        rule_parts = access_rule.get("rule", "").split()

        if len(rule_parts) < 1:
            return

        success = True
        if rule_parts[0].isdigit() and ACL_USE_EXISTING_SEQ == 'True':  # if isdigit, then has sequence number
            print('under True')
            seq_id = int(rule_parts[0])
            starting_index = 1
        elif rule_parts[0].isdigit() and ACL_USE_EXISTING_SEQ == 'False':  # if isdigit, then has sequence number
            seq_id = self.ace_seq_begin
            self.ace_seq_begin += 10
            starting_index = 1
        else:
            seq_id = self.ace_seq_begin
            self.ace_seq_begin += 10
            starting_index = 0
        if rule_parts[starting_index] == "remark":
            acls_note_add(f"""
                Access-list {self._xe_acl_set.get("id")} sequence number {seq_id} is a remark.
                ACL remarks are only supported in MDD OpenConfig using the forwarding action of "REMARK"
                You may want to consider how you want to handle your ACL remarks.:
                "{seq_id} {access_rule["rule"]}"
            """)
            entry = {
                "openconfig-acl:sequence-id": seq_id,
                "openconfig-acl:config": {
                    "openconfig-acl:sequence-id": seq_id,
                    "openconfig-acl:description": " ".join(rule_parts[starting_index + 1:])
                },
                "openconfig-acl:actions": {
                    "openconfig-acl:config": {
                        "openconfig-acl:forwarding-action": "REMARK"}
                }
            }
            acl_set["openconfig-acl:acl-entries"]["openconfig-acl:acl-entry"].append(entry)
            return success

        entry = {
            "openconfig-acl:sequence-id": seq_id,
            "openconfig-acl:config": {"openconfig-acl:sequence-id": seq_id},
            "openconfig-acl:actions": {
                "openconfig-acl:config": {"openconfig-acl:forwarding-action": actions_xe_to_oc[rule_parts[starting_index]]}
            }
        }

        try:
            current_index = self.__set_protocol(entry, rule_parts, starting_index)
            # Source IP
            current_index = self.__set_ip_and_port(rule_parts, current_index, entry, True, starting_index)
            if self._acl_type == "ACL_IPV4":
                # Destination IP (if exists)
                current_index = self.__set_ip_and_port(rule_parts, current_index, entry, False, starting_index)
            if (len(rule_parts) > current_index and rule_parts[current_index] == "log-input") or (
                    len(rule_parts) > current_index and rule_parts[current_index] == "log"):
                entry["openconfig-acl:actions"]["openconfig-acl:config"]["openconfig-acl:log-action"] = "LOG_SYSLOG"
            else:
                entry["openconfig-acl:actions"]["openconfig-acl:config"]["openconfig-acl:log-action"] = "LOG_NONE"

        except Exception as err:
            success = False

        if success:
            acl_set["openconfig-acl:acl-entries"]["openconfig-acl:acl-entry"].append(entry)

        return success

    def __add_acl_entry_note(self, original_entry, note):
        acls_notes.append(f"""
            ACL name: {self._xe_acl_name}
            Original ACL entry: {original_entry}
            {note} 
        """)

    def __set_protocol(self, entry, rule_parts, index):
        if self._acl_type == "ACL_IPV4_STANDARD":
            return index + 1
        if rule_parts[index + 1] != 'ip':
            if not rule_parts[index + 1] in protocols_oc_to_xe:
                self.__add_acl_entry_note(" ".join(rule_parts),
                                          f"protocol {rule_parts[index + 1]} does not exist in expected list of protocols")
                self.acl_success = False
                raise ValueError
            self.__get_ipv4_config(entry)["openconfig-acl:protocol"] = protocols_oc_to_xe[rule_parts[index + 1]]

        return index + 2

    def __get_ipv4_config(self, entry):
        if not self._ipv4_key in entry:
            entry[self._ipv4_key] = {}
        if not self._config_key in entry[self._ipv4_key]:
            entry[self._ipv4_key][self._config_key] = {}

        return entry[self._ipv4_key][self._config_key]

    def __get_transport_config(self, entry):
        if not "openconfig-acl:transport" in entry:
            entry["openconfig-acl:transport"] = {}
        if not "openconfig-acl:config" in entry["openconfig-acl:transport"]:
            entry["openconfig-acl:transport"]["openconfig-acl:config"] = {}

        return entry["openconfig-acl:transport"]["openconfig-acl:config"]

    def __set_ip_and_port(self, rule_parts, current_index, entry, is_source, index):
        if len(rule_parts) <= current_index:
            return current_index

        current_index = self.__set_ip_and_network(rule_parts, current_index, entry, is_source)

        if rule_parts[index + 1] == "tcp" or rule_parts[index + 1] == "udp":
            current_index = self.__set_port(rule_parts, current_index, entry, is_source)
        elif rule_parts[index + 1] == "icmp" and not is_source:
            current_index = self.__set_icmp(rule_parts, current_index, entry)

        return current_index

    def __set_ip_and_network(self, rule_parts, current_index, entry, is_source):
        ip = rule_parts[current_index]

        if ip == "any":
            if is_source:
                self.__get_ipv4_config(entry)[self._src_addr_key] = "0.0.0.0/0"
            else:
                self.__get_ipv4_config(entry)["openconfig-acl:destination-address"] = "0.0.0.0/0"

            return current_index + 1
        elif ip == "host":
            if is_source:
                self.__get_ipv4_config(entry)[self._src_addr_key] = f"{rule_parts[current_index + 1]}/32"
            else:
                self.__get_ipv4_config(entry)[
                    "openconfig-acl:destination-address"] = f"{rule_parts[current_index + 1]}/32"
            return current_index + 2
        elif (rule_parts[0].isdigit() and len(rule_parts) == 3) \
                or (rule_parts[0].isdigit() and len(rule_parts) == 4 and rule_parts[-1] == "log") \
                or (rule_parts[0].isdigit() and len(rule_parts) == 4 and rule_parts[-1] == "log-input") \
                or len(rule_parts) == 2 \
                or (len(rule_parts) == 3 and rule_parts[-1] == "log") \
                or (len(rule_parts) == 3 and rule_parts[-1] == "log-input"):
            self.__get_ipv4_config(entry)[self._src_addr_key] = f"{ip}/32"

            return current_index + 1
        elif not common.is_valid_ip(ip):
            return current_index
        
        hostmask = rule_parts[current_index + 1]
        
        if hostmask in port_operators:
            return current_index + 1
        
        try:
            temp_ip = IPv4Network((0, hostmask))
        except Exception as err:
            self.__add_acl_entry_note(" ".join(rule_parts), err)
            self.acl_success = False
            raise Exception(str(err))

        # 0.0.0.0 and 255.255.255.255 are wrong using IPv4Network.prefixlen()
        if hostmask == "0.0.0.0":
            prefixlen = "32"
        elif hostmask == "255.255.255.255":
            prefixlen = "0"
        else:
            prefixlen =temp_ip.prefixlen

        if is_source:
            self.__get_ipv4_config(entry)[self._src_addr_key] = f"{ip}/{prefixlen}"
        else:
            self.__get_ipv4_config(entry)["openconfig-acl:destination-address"] = f"{ip}/{prefixlen}"
        return current_index + 2

    def __set_port(self, rule_parts, current_index, entry, is_source):
        if len(rule_parts) <= current_index or not rule_parts[current_index] in port_operators:
            # We've either reached the end of the rule or there's no specified port
            if is_source:
                self.__get_transport_config(entry)["openconfig-acl:source-port"] = "ANY"
            else:
                self.__get_transport_config(entry)["openconfig-acl:destination-port"] = "ANY"
                current_index = self.__set_tcp_flags(rule_parts, current_index, entry)

            return current_index

        current_port = rule_parts[current_index + 1]

        try:
            current_port = current_port if current_port.isdigit() else socket.getservbyname(current_port)
        except OSError as os_err:
            try:
                current_port = common.port_name_number_mapping[current_port]
            except Exception as err:
                self.__add_acl_entry_note(" ".join(rule_parts),
                                          f"Unable to convert service {current_port} to a port number")
                self.acl_success = False
                raise Exception(str(os_err))

        if rule_parts[current_index] == "range":
            end_port = rule_parts[current_index + 2]

            if is_source:
                self.__get_transport_config(entry)["openconfig-acl:source-port"] = f"{current_port}..{end_port}"
            else:
                self.__get_transport_config(entry)["openconfig-acl:destination-port"] = f"{current_port}..{end_port}"
                current_index = self.__set_tcp_flags(rule_parts, current_index + 3, entry)

            return current_index + 3
        elif rule_parts[current_index] == "lt":
            if is_source:
                self.__get_transport_config(entry)["openconfig-acl:source-port"] = f"0..{int(current_port) - 1}"
            else:
                self.__get_transport_config(entry)["openconfig-acl:destination-port"] = f"0..{int(current_port) - 1}"
        elif rule_parts[current_index] == "gt":
            if is_source:
                self.__get_transport_config(entry)["openconfig-acl:source-port"] = f"{int(current_port) + 1}..65535"
            else:
                self.__get_transport_config(entry)[
                    "openconfig-acl:destination-port"] = f"{int(current_port) + 1}..65535"
        elif rule_parts[current_index] == "eq":
            if is_source:
                self.__get_transport_config(entry)["openconfig-acl:source-port"] = int(current_port)
            else:
                self.__get_transport_config(entry)["openconfig-acl:destination-port"] = int(current_port)
        elif rule_parts[current_index] == "neq":
            self.__add_acl_entry_note(" ".join(rule_parts),
                                      "XE ACL use of 'neq' port operator does not have an OC equivalent.")
            self.acl_success = False
            raise ValueError

        if not is_source:
            current_index = self.__set_tcp_flags(rule_parts, current_index + 2, entry)

        return current_index + 2

    def __set_icmp(self, rule_parts, current_index, entry):
        if len(rule_parts) <= current_index:
            # end of the rule or there's messages specified
            return current_index
        elif rule_parts[current_index] in icmp_names_to_types:
            msg, code = icmp_names_to_types[rule_parts[current_index]]
            entry['openconfig-acl-ext:icmp-v4'] = {'openconfig-acl-ext:config':
                                                       {'openconfig-acl-ext:type': msg,
                                                        'openconfig-acl-ext:code': code}}
            return current_index + 1
        elif rule_parts[current_index].isdigit():
            entry['openconfig-acl-ext:icmp-v4'] = {'openconfig-acl-ext:config':
                                                       {'openconfig-acl-ext:type': rule_parts[current_index],
                                                        'openconfig-acl-ext:code': 0}}
            if current_index + 1 < len(rule_parts) and rule_parts[current_index + 1].isdigit():
                entry['openconfig-acl-ext:icmp-v4']['openconfig-acl-ext:config']['openconfig-acl-ext:code'] = rule_parts[current_index + 1]
                return current_index + 2
            return current_index + 1
        else:
            return current_index


    def __set_tcp_flags(self, rule_parts, current_index, entry):
        if len(rule_parts) <= current_index or not rule_parts[current_index] in ["ack", "rst", "established"]:
            return current_index

        if rule_parts[current_index] == "ack":
            self.__get_transport_config(entry)["openconfig-acl:tcp-flags"] = ["TCP_ACK"]
        if rule_parts[current_index] == "rst":
            self.__get_transport_config(entry)["openconfig-acl:tcp-flags"] = ["TCP_RST"]
        if rule_parts[current_index] == "established":
            self.__get_transport_config(entry)["openconfig-acl:tcp-flags"] = ["TCP_ACK", "TCP_RST"]

        return current_index + 1


class StandardAcl(BaseAcl):
    def __init__(self, oc_acl_set, xe_acl_set, xe_acl_set_after):
        super(StandardAcl, self).__init__(oc_acl_set, xe_acl_set, xe_acl_set_after)
        self._rule_list_key = "std-access-list-rule"
        self._acl_type = "ACL_IPV4_STANDARD"
        self._ipv4_key = "openconfig-acl-ext:ipv4"
        self._config_key = "openconfig-acl-ext:config"
        self._src_addr_key = "openconfig-acl-ext:source-address"


class ExtendedAcl(BaseAcl):
    def __init__(self, oc_acl_set, xe_acl_set, xe_acl_set_after):
        super(ExtendedAcl, self).__init__(oc_acl_set, xe_acl_set, xe_acl_set_after)
        self._rule_list_key = "ext-access-list-rule"
        self._acl_type = "ACL_IPV4"
        self._ipv4_key = "openconfig-acl:ipv4"
        self._config_key = "openconfig-acl:config"
        self._src_addr_key = "openconfig-acl:source-address"


class NumberedStandardAcl(BaseAcl):
    def __init__(self, oc_acl_set, xe_acl_set, xe_acl_set_after):
        super(NumberedStandardAcl, self).__init__(oc_acl_set, xe_acl_set, xe_acl_set_after)
        self._xe_acl_name = self._xe_acl_set.get("id")
        self._xe_acl_key = "id"
        self._rule_list_key = "rule"
        self._acl_type = "ACL_IPV4_STANDARD"
        self._ipv4_key = "openconfig-acl-ext:ipv4"
        self._config_key = "openconfig-acl-ext:config"
        self._src_addr_key = "openconfig-acl-ext:source-address"


class NumberedExtendedAcl(BaseAcl):
    def __init__(self, oc_acl_set, xe_acl_set, xe_acl_set_after):
        super(NumberedExtendedAcl, self).__init__(oc_acl_set, xe_acl_set, xe_acl_set_after)
        self._xe_acl_name = self._xe_acl_set.get("id")
        self._xe_acl_key = "id"
        self._rule_list_key = "rule"
        self._acl_type = "ACL_IPV4"
        self._ipv4_key = "openconfig-acl:ipv4"
        self._config_key = "openconfig-acl:config"
        self._src_addr_key = "openconfig-acl:source-address"


def get_interfaces_by_acl(config_before, config_after):
    interfaces_by_acl = {}
    interfaces = config_before.get("tailf-ned-cisco-ios:interface", {})
    interfaces_after = config_after.get("tailf-ned-cisco-ios:interface", {})
    for interface_type, interface_list in interfaces.items():
        interface_list_after = interfaces_after[interface_type]

        if interface_type == "Port-channel-subinterface":
            interface_type = "Port-channel"
            interface_list = interface_list[interface_type]
            interface_list_after = interface_list_after[interface_type]

        if interface_type == "LISP-subinterface":
            interface_type = "LISP"
            interface_list = interface_list[interface_type]
            interface_list_after = interface_list_after[interface_type]

        for index, interface in enumerate(interface_list):
            if not "ip" in interface or not "access-group" in interface["ip"] or len(
                    interface["ip"]["access-group"]) < 1:
                continue

            intf_id = f"{interface_type}{interface['name']}"
            intf_numb_parts = re.split("[.]", str(interface["name"]))
            intf_num = intf_numb_parts[0]
            subintf_num = int(intf_numb_parts[1]) if len(intf_numb_parts) > 1 else 0

            for access_group in interface["ip"]["access-group"]:
                if interface_list_after[index].get("ip") and interface_list_after[index]["ip"].get("access-group"):
                    del interface_list_after[index]["ip"]["access-group"]

                if (interface_type != "Tunnel") and (interface_type != "Vlan"):  # no sub-ifs for these
                    intf = {
                        "id": intf_id,
                        "interface": f"{interface_type}{intf_num}",
                        "subinterface": subintf_num,
                        "direction": access_group["direction"]
                    }
                else:
                    intf = {
                        "id": intf_id,
                        "interface": f"{interface_type}{intf_num}",
                        "direction": access_group["direction"]
                    }

                if not access_group["access-list"] in interfaces_by_acl:
                    interfaces_by_acl[access_group["access-list"]] = []

                interfaces_by_acl[access_group["access-list"]].append(intf)

    return interfaces_by_acl


def process_interfaces(acl_type, acl_name, interfaces_by_acl, acl_interfaces):
    interfaces = interfaces_by_acl.get(acl_name, [])

    for interface in interfaces:
        if interface["id"] in acl_interfaces:
            acl_interface = acl_interfaces[interface["id"]]
        elif interface.get("subinterface"):
            acl_interface = {
                "openconfig-acl:id": interface["id"],
                "openconfig-acl:config": {"openconfig-acl:id": interface["id"]},
                "openconfig-acl:interface-ref": {
                    "openconfig-acl:config": {
                        "openconfig-acl:interface": interface["interface"],
                        "openconfig-acl:subinterface": interface["subinterface"]
                    }
                }
            }
        else:
            acl_interface = {
                "openconfig-acl:id": interface["id"],
                "openconfig-acl:config": {"openconfig-acl:id": interface["id"]},
                "openconfig-acl:interface-ref": {
                    "openconfig-acl:config": {
                        "openconfig-acl:interface": interface["interface"]
                    }
                }
            }
            acl_interfaces[interface["id"]] = acl_interface

        intf_acl_set = get_intf_acl_set(acl_interface, interface["direction"])
        intf_acl_set.append({
            "openconfig-acl:set-name": acl_name,
            "openconfig-acl:type": acl_type,
            "openconfig-acl:config": {
                "openconfig-acl:set-name": acl_name,
                "openconfig-acl:type": acl_type
            }
        })


def get_intf_acl_set(acl_interface, direction):
    if direction == "in":
        ingress_set = "openconfig-acl:ingress-acl-set"
        if not f"{ingress_set}s" in acl_interface:
            acl_interface[f"{ingress_set}s"] = {ingress_set: []}
        if not ingress_set in acl_interface[f"{ingress_set}s"]:
            acl_interface[f"{ingress_set}s"][ingress_set] = []

        return acl_interface[f"{ingress_set}s"][ingress_set]
    else:
        egress_set = "openconfig-acl:egress-acl-set"
        if not f"{egress_set}s" in acl_interface:
            acl_interface[f"{egress_set}s"] = {egress_set: []}
        if not egress_set in acl_interface[f"{egress_set}s"]:
            acl_interface[f"{egress_set}s"][egress_set] = []

        return acl_interface[f"{egress_set}s"][egress_set]


def process_ntp(config_before, config_after):
    ntp_access_group = config_before.get("tailf-ned-cisco-ios:ntp", {}).get("access-group", {})
    ntp_access_group_after = config_after.get("tailf-ned-cisco-ios:ntp", {}).get("access-group", {})

    if ntp_access_group.get("serve") and ntp_access_group["serve"].get("access-list"):
        openconfig_acls["openconfig-acl:acl"]["openconfig-acl-ext:ntp"] = {
            "openconfig-acl-ext:server": {
                "openconfig-acl-ext:config": {
                    "openconfig-acl-ext:server-acl-set": ntp_access_group["serve"]["access-list"]
                }
            }
        }
        del ntp_access_group_after["serve"]["access-list"]
    if ntp_access_group.get("peer") and ntp_access_group["peer"].get("access-list"):
        ntp_peer = {
            "openconfig-acl-ext:peer": {
                "openconfig-acl-ext:config": {
                    "openconfig-acl-ext:peer-acl-set": ntp_access_group["peer"]["access-list"]
                }
            }
        }

        if openconfig_acls["openconfig-acl:acl"].get("openconfig-acl-ext:ntp"):
            openconfig_acls["openconfig-acl:acl"]["openconfig-acl-ext:ntp"].update(ntp_peer)
        else:
            openconfig_acls["openconfig-acl:acl"]["openconfig-acl-ext:ntp"] = ntp_peer

        del ntp_access_group_after["peer"]["access-list"]


def process_line(config_before, config_after):
    vty_accesses = config_before.get("tailf-ned-cisco-ios:line", {}).get("vty")
    vty_accesses_after = config_after.get("tailf-ned-cisco-ios:line", {}).get("vty")
    openconfig_acls["openconfig-acl:acl"]["openconfig-acl-ext:lines"] = {"openconfig-acl-ext:line": []}
    acl_line = openconfig_acls["openconfig-acl:acl"]["openconfig-acl-ext:lines"]["openconfig-acl-ext:line"]

    for index, access in enumerate(vty_accesses):
        line_item = {
            "openconfig-acl-ext:id": f"vty {access['first']} {access['last']}",
            "openconfig-acl-ext:config": {
                "openconfig-acl-ext:id": f"vty {access['first']} {access['last']}"
            }
        }
        if ("access-class" in access and "access-list" in access["access-class"]) or (
                "access-class-vrf" in access and "access-class" in access["access-class-vrf"]):
            acl_line.append(line_item)

        if "access-class" in access and "access-list" in access["access-class"]:
            process_vrf(access["access-class"]["access-list"], line_item)
            del vty_accesses_after[index]["access-class"]["access-list"]
        elif "access-class-vrf" in access and "access-class" in access["access-class-vrf"]:
            process_vrf(access["access-class-vrf"]["access-class"], line_item)
            del vty_accesses_after[index]["access-class-vrf"]["access-class"]


def process_vrf(access_list, line_item):
    for access in access_list:
        if access["direction"] == "out":
            line_item["openconfig-acl-ext:egress-acl-set"] = access["access-list"]
        else:
            line_item["openconfig-acl-ext:ingress-acl-sets"] = {
                "openconfig-acl-ext:ingress-acl-set": [
                    {
                        "openconfig-acl-ext:ingress-acl-set-name": access["access-list"],
                        "openconfig-acl-ext:config": {
                            "openconfig-acl-ext:vrf": access["vrfname"] if "vrfname" in access else "global",
                            "openconfig-acl-ext:vrf-also": "vrf-also" in access,
                            "openconfig-acl-ext:ingress-acl-set-name": access["access-list"]
                        }
                    }
                ]
            }


def main(before: dict, leftover: dict, translation_notes: list = []) -> dict:
    """
    Translates NSO Device configurations to MDD OpenConfig configurations.

    Requires environment variables:
    NSO_URL: str
    NSO_USERNAME: str
    NSO_PASSWORD: str
    NSO_DEVICE: str
    TEST - If True, sends generated OC configuration to NSO Server: str

    :param before: Original NSO Device configuration: dict
    :param leftover: NSO Device configuration minus configs replaced with MDD OC: dict
    :param translation_notes: notes from previous NSO to OC translations if any
    :return: MDD Openconfig Network Instances configuration: dict
    """
    xe_acls(before, leftover)
    translation_notes += acls_notes

    return openconfig_acls


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
    config_name = "_acls"
    config_remaining_name = "_remaining_acls"
    oc_name = "_openconfig_acls"
    common.print_and_test_configs(
        "xe1", config_before_dict, config_leftover_dict, openconfig_acls,
        config_name, config_remaining_name, oc_name, acls_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc import common
    else:
        from xe import common_xe
        import common
