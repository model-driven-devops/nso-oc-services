# -*- mode: python; python-indent: 4 -*-
import re

from translation.openconfig_xe.common import prefix_to_network_and_mask
from translation.openconfig_xe.common import xe_get_interface_type_and_number

regex_ports = re.compile(r'(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[0-5][0-9]{4}|[0-9]{1,4})\.\.(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[0-5][0-9]{4}|[0-9]{1,4})')


def xe_acls_program_service(self) -> None:
    """
    Program service for xe NED features
    """
    protocols_oc_to_xe = {1: 'icmp',
                          'oc-pkt-match-types:IP_ICMP': 'icmp',
                          2: 'igmp',
                          'oc-pkt-match-types:IP_IGMP': 'igmp',
                          4: 'ipinip',
                          'oc-pkt-match-types:IP_IN_IP': 'ipnip',
                          6: 'tcp',
                          'oc-pkt-match-types:IP_TCP': 'tcp',
                          17: 'udp',
                          'oc-pkt-match-types:IP_UDP': 'udp',
                          47: 'gre',
                          'oc-pkt-match-types:IP_GRE': 'gre',
                          51: 'ahp',
                          'oc-pkt-match-types:IP_AUTH': 'ahp',
                          103: 'pim',
                          'oc-pkt-match-types:IP_PIM': 'pim'}

    actions_oc_to_xe = {'oc-acl:ACCEPT': 'permit',
                        'oc-acl:DROP': 'deny',
                        'oc-acl:REJECT': 'deny'}
    device = self.root.devices.device[self.device_name].config
    for service_acl in self.service.oc_acl__acl.acl_sets.acl_set:
        if service_acl.type == 'oc-acl:ACL_IPV4':
            if not device.ios__ip.access_list.extended.ext_named_acl.exists(service_acl.name):
                device.ios__ip.access_list.extended.ext_named_acl.create(service_acl.name)

            acl = device.ios__ip.access_list.extended.ext_named_acl[service_acl.name]
            rules_oc_config = list()  # {'10 permit tcp any 1.1.1.1 0.0.0.0 eq 80'}

            for i in service_acl.acl_entries.acl_entry:
                rule = str(i.sequence_id) + ' ' + actions_oc_to_xe[i.actions.config.forwarding_action] + ' '
                if i.ipv4.config.protocol:
                    rule += protocols_oc_to_xe[i.ipv4.config.protocol] + ' '
                else:
                    rule += 'ip' + ' '
                if i.ipv4.config.source_address == '0.0.0.0/0':
                    rule += 'any '
                else:
                    rule += prefix_to_network_and_mask(i.ipv4.config.source_address) + ' '
                if (i.ipv4.config.protocol == 'oc-pkt-match-types:IP_TCP') or \
                        (i.ipv4.config.protocol == 'oc-pkt-match-types:IP_UDP'):
                    if i.transport.config.source_port:
                        source_port = str(i.transport.config.source_port)
                        if source_port == 'ANY':
                            pass
                        elif source_port.isdigit():
                            rule += 'eq ' + source_port + ' '
                        elif regex_ports.match(source_port):
                            result = regex_ports.search(source_port)
                            ml = [int(result.group(1)), int(result.group(2))]
                            ml.sort()
                            rule += f'range {ml[0]} {ml[1]} '
                if i.ipv4.config.destination_address == '0.0.0.0/0':
                    rule += 'any '
                else:
                    rule += prefix_to_network_and_mask(i.ipv4.config.destination_address) + ' '
                if (i.ipv4.config.protocol == 'oc-pkt-match-types:IP_TCP') or \
                        (i.ipv4.config.protocol == 'oc-pkt-match-types:IP_UDP'):
                    if i.transport.config.destination_port:
                        dest_port = str(i.transport.config.destination_port)
                        if dest_port == 'ANY':
                            pass
                        elif dest_port.isdigit():
                            rule += 'eq ' + dest_port + ' '
                        elif regex_ports.match(dest_port):
                            result = regex_ports.search(dest_port)
                            ml = [int(result.group(1)), int(result.group(2))]
                            ml.sort()
                            rule += f'range {ml[0]} {ml[1]} '
                    if i.transport.config.tcp_flags:
                        if (len(i.transport.config.tcp_flags) == 1) and (
                                i.transport.config.tcp_flags[0] == 'TCP_ACK'):
                            rule += 'ack '
                        elif (len(i.transport.config.tcp_flags) == 1) and (
                                i.transport.config.tcp_flags[0] == 'TCP_RST'):
                            rule += 'rst '
                        elif (len(i.transport.config.tcp_flags) == 2) and \
                                ('TCP_ACK' in i.transport.config.tcp_flags) and \
                                ('TCP_RST' in i.transport.config.tcp_flags):
                            rule += 'established '
                if i.actions.config.log_action:
                    if i.actions.config.log_action == 'oc-acl:LOG_SYSLOG':
                        rule += 'log-input'
                rules_oc_config.append(rule)
            for i in rules_oc_config:
                self.log.debug(f'{self.device_name} ACL {service_acl.name} ACE: {i}')
                acl.ext_access_list_rule.create(i)

        if service_acl.type == 'oc-acl-ext:ACL_IPV4_STANDARD':
            if not device.ios__ip.access_list.standard.std_named_acl.exists(service_acl.name):
                device.ios__ip.access_list.standard.std_named_acl.create(service_acl.name)
            acl = device.ios__ip.access_list.standard.std_named_acl[service_acl.name]
            rules_oc_config = list()  # {'10 permit any'}
            for i in service_acl.acl_entries.acl_entry:
                rule = str(i.sequence_id) + ' ' + actions_oc_to_xe[i.actions.config.forwarding_action] + ' '
                if i.oc_acl_ext__ipv4.source_address == '0.0.0.0/0':
                    rule += 'any '
                else:
                    rule += prefix_to_network_and_mask(i.oc_acl_ext__ipv4.source_address) + ' '
                if i.actions.config.log_action:
                    if i.actions.config.log_action == 'oc-acl:LOG_SYSLOG':
                        rule += 'log-input'
                rules_oc_config.append(rule)
            for i in rules_oc_config:
                self.log.debug(f'{self.device_name} ACL {service_acl.name} ACE: {i}')
                acl.std_access_list_rule.create(i)


def xe_acls_interfaces_program_service(self) -> None:
    """
    Program xe interfaces ingress and egress acls
    """
    for service_acl_interface in self.service.oc_acl__acl.interfaces.interface:
        # Get interface object
        interface_type, interface_number = xe_get_interface_type_and_number(
            service_acl_interface.interface_ref.config.interface)
        class_attribute = getattr(self.root.devices.device[self.device_name].config.ios__interface,
                                  interface_type)
        if service_acl_interface.interface_ref.config.subinterface == 0 or not service_acl_interface.interface_ref.config.subinterface:
            interface_cdb = class_attribute[interface_number]
        else:
            interface_cdb = class_attribute[f'{interface_number}.{service_acl_interface.interface_ref.config.subinterface}']

        # Apply ACLs  TODO add other ACL types
        if service_acl_interface.egress_acl_sets:
            for acl in service_acl_interface.egress_acl_sets.egress_acl_set:
                if acl.type == 'oc-acl:ACL_IPV4':
                    if not interface_cdb.ip.access_group.exists('out'):
                        interface_cdb.ip.access_group.create('out')
                    interface_cdb.ip.access_group['out'].access_list = acl.set_name
                    self.log.info(f'{self.device_name} ACL {acl.set_name} added to interface {service_acl_interface.id} egress')
                if acl.type == 'oc-acl-ext:ACL_IPV4_STANDARD':
                    if not interface_cdb.ip.access_group.exists('out'):
                        interface_cdb.ip.access_group.create('out')
                    interface_cdb.ip.access_group['out'].access_list = acl.set_name
                    self.log.info(f'{self.device_name} ACL {acl.set_name} added to interface {service_acl_interface.id} egress')
        if service_acl_interface.ingress_acl_sets:
            for acl in service_acl_interface.ingress_acl_sets.ingress_acl_set:
                if acl.type == 'oc-acl:ACL_IPV4':
                    if not interface_cdb.ip.access_group.exists('in'):
                        interface_cdb.ip.access_group.create('in')
                    interface_cdb.ip.access_group['in'].access_list = acl.set_name
                    self.log.info(f'{self.device_name} ACL {acl.set_name} added to interface {service_acl_interface.id} ingress')
                if acl.type == 'oc-acl-ext:ACL_IPV4_STANDARD':
                    if not interface_cdb.ip.access_group.exists('in'):
                        interface_cdb.ip.access_group.create('in')
                    interface_cdb.ip.access_group['in'].access_list = acl.set_name
                    self.log.info(f'{self.device_name} ACL {acl.set_name} added to interface {service_acl_interface.id} ingress')


def xe_acls_lines_program_service(self) -> None:
    """
    Program xe lines ingress and egress acls
    """
    device = self.root.devices.device[self.device_name].config
    for service_line in self.service.oc_acl__acl.oc_acl_ext__lines.line:
        if 'vty ' in service_line.id.lower():
            matches = re.findall(r'[0-9]+', service_line.id)
            if len(matches) == 2:
                line_start = int(matches[0])
                line_end = int(matches[1])
                if service_line.egress_acl_set:
                    config_obj = device.ios__line.vty.create(line_start, line_end)
                    acl_object = config_obj.access_class.access_list.create('out')
                    acl_object.access_list = service_line.egress_acl_set
                if service_line.ingress_acl_sets.ingress_acl_set:
                    for service_ingress in service_line.ingress_acl_sets.ingress_acl_set:
                        if service_ingress.config.vrf == 'global':
                            config_obj = device.ios__line.vty.create(line_start, line_end)
                            acl_object = config_obj.access_class.access_list.create('in')
                            acl_object.access_list = service_ingress.config.ingress_acl_set_name
                            if service_ingress.config.vrf_also:
                                acl_object.vrf_also.create()
                        else:
                            config_obj = device.ios__line.vty.create(line_start, line_end)
                            acl_object = config_obj.access_class.access_list.create('in')
                            acl_object.access_list = service_ingress.config.ingress_acl_set_name
                            acl_object.vrfname = service_ingress.config.vrf
            else:
                raise ValueError('line vty takes a start and an end line number range')


def xe_acls_ntp_program_service(self) -> None:
    """
    Apply NTP ACLs
    """
    device = self.root.devices.device[self.device_name].config
    # Serve
    if self.service.oc_acl__acl.oc_acl_ext__ntp.serve.serve_acl_set:
        device.ios__ntp.access_group.serve.access_list = self.service.oc_acl__acl.oc_acl_ext__ntp.serve.serve_acl_set
    else:
        device.ios__ntp.access_group.serve.access_list = None
    # Peer
    if self.service.oc_acl__acl.oc_acl_ext__ntp.peer.peer_acl_set:
        device.ios__ntp.access_group.peer.access_list = self.service.oc_acl__acl.oc_acl_ext__ntp.peer.peer_acl_set
    else:
        device.ios__ntp.access_group.peer.access_list = None
