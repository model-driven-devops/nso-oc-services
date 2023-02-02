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
import socket
import re

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
protocols_oc_to_xr = {
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
# OC has an additional forwarding action, "DROP", which also translates to "deny" in XR.
actions_xr_to_oc = {
    "permit": "ACCEPT",
    "deny": "REJECT",
}
port_operators = ["range", "eq", "lt", "gt", "neq"]
ACL_EXT_TYPE = "ACL_IPV4"


def xr_acls(config_before, config_after):
    oc_acl_set = openconfig_acls["openconfig-acl:acl"]["openconfig-acl:acl-sets"]["openconfig-acl:acl-set"]
    oc_acl_interface = openconfig_acls["openconfig-acl:acl"]["openconfig-acl:interfaces"]["openconfig-acl:interface"]
    access_list = config_before.get("tailf-ned-cisco-ios-xr:ipv4", {}).get("access-list", {})
    access_list_after = config_after.get("tailf-ned-cisco-ios-xr:ipv4", {}).get("access-list", {})
    interfaces_by_acl = get_interfaces_by_acl(config_before, config_after)
    acl_interfaces = {}

    for ext_index, ext_acl in enumerate(access_list.get("named-acl", [])):
        extended_acl = ExtendedAcl(oc_acl_set, ext_acl["rule"], ext_acl["name"],
                                   access_list_after["named-acl"][ext_index])
        extended_acl.process_acl()
        process_interfaces(ACL_EXT_TYPE, ext_acl["name"], interfaces_by_acl, acl_interfaces)

    for interface in acl_interfaces.values():
        oc_acl_interface.append(interface)

    process_ntp(config_before, config_after)
    process_line(config_before, config_after)


class BaseAcl:
    def __init__(self, oc_acl_set, xr_acl_set, xr_acl_name, xr_acl_set_after):
        self._oc_acl_set = oc_acl_set
        self._xr_acl_set = xr_acl_set
        self._xr_acl_set_after = xr_acl_set_after
        self._xr_acl_name = xr_acl_name
        self.acl_success = True

    def process_acl(self):
        acl_set = {
            "openconfig-acl:name": self._xr_acl_name,
            "openconfig-acl:type": self._acl_type,
            "openconfig-acl:config": {
                "openconfig-acl:name": self._xr_acl_name,
                "openconfig-acl:type": self._acl_type,
                "openconfig-acl:description": self._xr_acl_name,  # XR doesn't seem to have a description.
            },
            "openconfig-acl:acl-entries": {
                "openconfig-acl:acl-entry": []
            }
        }
        self.acl_success = True

        for rule_index, access_rule in enumerate(self._xr_acl_set):
            rule_success = self.__set_rule_parts(access_rule, acl_set)

            if rule_success:
                self._xr_acl_set_after['rule'][rule_index] = None
            else:
                self.acl_success = False

        # We only delete if all entries processed successfully.
        # We only add the ACL to OpenConfig if all entries processed successfully.
        if self.acl_success:
            self._oc_acl_set.append(acl_set)
            del self._xr_acl_set_after["name"]

    def __set_rule_parts(self, access_rule, acl_set):
        rule_parts = access_rule.get("line", "").split()

        if len(rule_parts) < 1:
            return

        success = True
        seq_id = access_rule.get("id")
        entry = {
            "openconfig-acl:sequence-id": seq_id,
            "openconfig-acl:config": {"openconfig-acl:sequence-id": seq_id},
            "openconfig-acl:actions": {
                "openconfig-acl:config": {"openconfig-acl:forwarding-action": actions_xr_to_oc[rule_parts[0]]}
            }
        }
        try:
            current_index = self.__set_protocol(entry, rule_parts)
            # Source IP
            current_index = self.__set_ip_and_port(rule_parts, current_index, entry, True)
            if self._acl_type == "ACL_IPV4":
                # Destination IP (if exists)
                current_index = self.__set_ip_and_port(rule_parts, current_index, entry, False)
        except Exception as err:
            success = False

        if (len(rule_parts) > current_index and rule_parts[current_index] == "log-input") or (
                len(rule_parts) > current_index and rule_parts[current_index] == "log"):
            entry["openconfig-acl:actions"]["openconfig-acl:config"]["openconfig-acl:log-action"] = "LOG_SYSLOG"
        else:
            entry["openconfig-acl:actions"]["openconfig-acl:config"]["openconfig-acl:log-action"] = "LOG_NONE"

        if success:
            acl_set["openconfig-acl:acl-entries"]["openconfig-acl:acl-entry"].append(entry)

        return success

    def __add_acl_entry_note(self, original_entry, note):
        acls_notes.append(f"""
            ACL name: {self._xr_acl_name}
            Original ACL entry: {original_entry}
            {note} 
        """)

    def __set_protocol(self, entry, rule_parts):
        if rule_parts[1] != 'ipv4':
            if not rule_parts[1] in protocols_oc_to_xr:
                self.__add_acl_entry_note(" ".join(rule_parts),
                                          f"protocol {rule_parts[1]} does not exist in expected list of protocols")
                self.acl_success = False
                raise ValueError
            self.__get_ipv4_config(entry)["openconfig-acl:protocol"] = protocols_oc_to_xr[rule_parts[1]]

        return 2

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

    def __set_ip_and_port(self, rule_parts, current_index, entry, is_source):
        if len(rule_parts) <= current_index:
            return current_index

        current_index = self.__set_ip_and_network(rule_parts, current_index, entry, is_source)

        if rule_parts[1] == "tcp" or rule_parts[1] == "udp":
            current_index = self.__set_port(rule_parts, current_index, entry, is_source)

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

        hostmask = rule_parts[current_index + 1]
        temp_ip = IPv4Network((0, hostmask))

        # 0.0.0.0 and 255.255.255.255 are wrong using IPv4Network.prefixlen()
        if hostmask == "0.0.0.0":
            prefixlen = "32"
        elif hostmask == "255.255.255.255":
            prefixlen = "0"
        else:
            prefixlen = temp_ip.prefixlen

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
        except OSError:
            try:
                current_port = common.port_name_number_mapping[current_port]
            except Exception as err:
                self.__add_acl_entry_note(" ".join(rule_parts),
                                          f"Unable to convert service {current_port} to a port number")
                self.acl_success = False
                raise Exception

        if rule_parts[current_index] == "range":
            end_port = rule_parts[current_index + 2]

            if is_source:
                self.__get_transport_config(entry)["openconfig-acl:source-port"] = f"{current_port}..{end_port}"
            else:
                self.__get_transport_config(entry)["openconfig-acl:destination-port"] = f"{current_port}..{end_port}"
                current_index = self.__set_tcp_flags(rule_parts, current_index + 3, entry)

            return current_index
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
                                      "XR ACL use of 'neq' port operator does not have an OC equivalent.")
            self.acl_success = False
            raise ValueError

        if not is_source:
            current_index = self.__set_tcp_flags(rule_parts, current_index + 2, entry)

        return current_index + 2

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


class ExtendedAcl(BaseAcl):
    def __init__(self, oc_acl_set, xr_acl_set, xr_acl_name, xr_acl_set_after):
        super(ExtendedAcl, self).__init__(oc_acl_set, xr_acl_set, xr_acl_name, xr_acl_set_after)
        self._rule_list_key = "named-acl"
        self._acl_type = "ACL_IPV4"
        self._ipv4_key = "openconfig-acl:ipv4"
        self._config_key = "openconfig-acl:config"
        self._src_addr_key = "openconfig-acl:source-address"


def get_interfaces_by_acl(config_before, config_after):
    interfaces_by_acl = {}
    interfaces = config_before.get("tailf-ned-cisco-ios-xr:interface", {})
    interfaces_after = config_after.get("tailf-ned-cisco-ios-xr:interface", {})
    for interface_type, interface_list in interfaces.items():
        interface_list_after = interfaces_after[interface_type]

        if "-subinterface" in interface_type:
            interface_list = interface_list[interface_type.replace("-subinterface", "")]
            interface_list_after = interface_list_after[interface_type.replace("-subinterface", "")]
            interface_type = interface_type.replace("-subinterface", "")
        if interface_type == "Bundle-Ether":
            interface_type = "Port-channel"

        for index, interface in enumerate(interface_list):
            if not "ipv4" in interface or not "access-group" in interface["ipv4"] or len(
                    interface["ipv4"]["access-group"]) < 1:
                continue

            intf_id = f"{interface_type}{interface['id']}"
            intf_numb_parts = re.split("[.]", interface["id"])
            intf_num = intf_numb_parts[0]
            subintf_num = int(intf_numb_parts[1]) if len(intf_numb_parts) > 1 else 0

            for access_group in interface["ipv4"]["access-group"]:
                if interface_list_after[index].get("ipv4") and interface_list_after[index]["ipv4"].get("access-group"):
                    del interface_list_after[index]["ipv4"]["access-group"]

                intf = {
                    "id": intf_id,
                    "interface": f"{interface_type}{intf_num}",
                    "subinterface": subintf_num,
                    "direction": access_group["direction"]
                }

                if not access_group["name"] in interfaces_by_acl:
                    interfaces_by_acl[access_group["name"]] = []

                interfaces_by_acl[access_group["name"]].append(intf)

    return interfaces_by_acl


def process_interfaces(acl_type, acl_name, interfaces_by_acl, acl_interfaces):
    interfaces = interfaces_by_acl.get(acl_name, [])

    for interface in interfaces:
        if interface["id"] in acl_interfaces:
            acl_interface = acl_interfaces[interface["id"]]
        else:
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
    if direction == "ingress":
        ingress_set = "openconfig-acl:ingress-acl-set"
        if not f"{ingress_set}s" in acl_interface:
            acl_interface[f"{ingress_set}s"] = {ingress_set: []}
        if not ingress_set in acl_interface[f"{ingress_set}s"]:
            acl_interface[f"{ingress_set}s"][ingress_set] = []

        return acl_interface[f"{ingress_set}s"][ingress_set]
    elif direction == "egress":
        egress_set = "openconfig-acl:egress-acl-set"
        if not f"{egress_set}s" in acl_interface:
            acl_interface[f"{egress_set}s"] = {egress_set: []}
        if not egress_set in acl_interface[f"{egress_set}s"]:
            acl_interface[f"{egress_set}s"][egress_set] = []

        return acl_interface[f"{egress_set}s"][egress_set]
    else:
        raise ValueError("XR ACL not applied to interface with ingress or egress direction.")


def process_ntp(config_before, config_after):
    ntp_access_group = config_before.get("tailf-ned-cisco-ios-xr:ntp", {}).get("access-group", [])
    ntp_access_group_after = config_after.get("tailf-ned-cisco-ios-xr:ntp", {}).get("access-group", [])
    for acl_index, access_group in enumerate(ntp_access_group):

        if access_group.get("type") == "serve":
            ntp_peer = {
                "openconfig-acl-ext:server": {
                    "openconfig-acl-ext:config": {
                        "openconfig-acl-ext:server-acl-set": access_group.get("name")
                    }
                }
            }
            ntp_access_group_after[acl_index]["name"] = None
            ntp_access_group_after[acl_index]["type"] = None

        elif access_group.get("type") == "peer":
            ntp_peer = {
                "openconfig-acl-ext:peer": {
                    "openconfig-acl-ext:config": {
                        "openconfig-acl-ext:peer-acl-set": access_group.get("name")
                    }
                }
            }
            ntp_access_group_after[acl_index]["name"] = None
            ntp_access_group_after[acl_index]["type"] = None

        if ntp_peer:
            if openconfig_acls["openconfig-acl:acl"].get("openconfig-acl-ext:ntp"):
                openconfig_acls["openconfig-acl:acl"]["openconfig-acl-ext:ntp"].update(ntp_peer)
            else:
                openconfig_acls["openconfig-acl:acl"]["openconfig-acl-ext:ntp"] = ntp_peer


def check_default_profile_for_all_vty_lines(config_before) -> bool:
    """return True if default profile contains all vty-lines"""
    if not config_before.get("tailf-ned-cisco-ios-xr:vty-pool") or (
            len(config_before.get("tailf-ned-cisco-ios-xr:vty-pool")) == 1 and config_before.get(
        "tailf-ned-cisco-ios-xr:vty-pool").get("default")):
        return True
    elif config_before.get("tailf-ned-cisco-ios-xr:vty-pool", {}).get("default", {}).get(
            "first-vty") == 0 and config_before.get("tailf-ned-cisco-ios-xr:vty-pool", {}).get("default").get(
        "first-vty") == 99:
        return True
    else:
        return False


def acls_note_add(note):
    acls_notes.append(note)


def process_line(config_before, config_after):
    for name, line_item in config_before.get("tailf-ned-cisco-ios-xr:line", {}).items():
        if name == "default" and line_item.get("access-class"):
            openconfig_acls["openconfig-acl:acl"]["openconfig-acl-ext:lines"] = {"openconfig-acl-ext:line": []}
            acl_lines = openconfig_acls["openconfig-acl:acl"]["openconfig-acl-ext:lines"]["openconfig-acl-ext:line"]
            if not check_default_profile_for_all_vty_lines(config_before):
                access_group = f'{line_item.get("access-class").get("ingress")} {line_item.get("access-class").get("egress")}'
                acls_note_add(f"""
                    Could not apply VTY access group(s) {access_group}
                    MDD OpenConfig does not support multiple VTY line profiles.
                    Ensure all VTY lines (0 - 99) are in the 'default' VTY line profile.
                """)
            else:
                if line_item.get("access-class").get("ingress"):
                    acl_lines.append({
                        "openconfig-acl-ext:id": "vty 0 99",
                        "openconfig-acl-ext:config": {
                            "openconfig-acl-ext:id": "vty 0 99"},
                        "openconfig-acl-ext:ingress-acl-sets": {
                            "openconfig-acl-ext:ingress-acl-set": [
                                {"openconfig-acl-ext:ingress-acl-set-name": line_item.get("access-class").get(
                                    "ingress"),
                                    "openconfig-acl-ext:config": {
                                        "openconfig-acl-ext:ingress-acl-set-name": line_item.get("access-class").get(
                                            "ingress")}}]}})
                    config_after["tailf-ned-cisco-ios-xr:line"]["default"]["access-class"]["ingress"] = None
                if line_item.get("access-class").get("egress"):
                    acl_lines.append({
                        "openconfig-acl-ext:id": "vty 0 99",
                        "openconfig-acl-ext:config": {
                            "openconfig-acl-ext:id": "vty 0 99"},
                        "openconfig-acl-ext:egress-acl-set": line_item.get("access-class").get("egress")
                    })
                    config_after["tailf-ned-cisco-ios-xr:line"]["default"]["access-class"]["egress"] = None


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
    xr_acls(before, leftover)
    translation_notes += acls_notes

    return openconfig_acls


if __name__ == "__main__":
    sys.path.append("../../")
    sys.path.append("../../../")

    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xr import common_xr
        from package_nso_to_oc import common
    else:
        import common_xr
        import common

    (config_before_dict, config_leftover_dict) = common_xr.init_xr_configs()
    main(config_before_dict, config_leftover_dict)
    config_name = "_acls"
    config_remaining_name = "_remaining_acls"
    oc_name = "_openconfig_acls"
    common.print_and_test_configs(
        "xr1", config_before_dict, config_leftover_dict, openconfig_acls,
        config_name, config_remaining_name, oc_name, acls_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xr import common_xr
        from package_nso_to_oc import common
    else:
        from xr import common_xr
        import common
