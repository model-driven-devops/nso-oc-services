# -*- mode: python; python-indent: 4 -*-
import re

from translation.common import prefix_to_network_and_mask
from translation.common import get_interface_type_and_number

regex_ports = re.compile(r'(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[0-5][0-9]{4}|[0-9]{1,4})\.\.(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[0-5][0-9]{4}|[0-9]{1,4})')


def xr_acls_program_service(self) -> None:
    """
    Program service for xr NED features
    """
    protocols_oc_to_xr = {1: 'icmp',
                          'oc-pkt-match-types:IP_ICMP': 'icmp',
                          2: 'igmp',
                          'oc-pkt-match-types:IP_IGMP': 'igmp',
                          4: 'ipinip',
                          'oc-pkt-match-types:IP_IN_IP': 'ipinip',
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

    actions_oc_to_xr = {'oc-acl:ACCEPT': 'permit',
                        'oc-acl:DROP': 'deny',
                        'oc-acl:REJECT': 'deny'}
    device = self.root.devices.device[self.device_name].config
    for service_acl in self.service.oc_acl__acl.acl_sets.acl_set:
        if service_acl.type == 'oc-acl:ACL_IPV4':
            if device.cisco_ios_xr__ipv4.access_list.named_acl.exists(service_acl.name):
                del device.cisco_ios_xr__ipv4.access_list.named_acl[service_acl.name]
            device.cisco_ios_xr__ipv4.access_list.named_acl.create(service_acl.name)

            acl = device.cisco_ios_xr__ipv4.access_list.named_acl[service_acl.name]
            rules_oc_config = list()  # {'10 permit tcp any 1.1.1.1 0.0.0.0 eq 80'}

            for i in service_acl.acl_entries.acl_entry:
                rule = actions_oc_to_xr[i.actions.config.forwarding_action] + ' '
                if i.ipv4.config.protocol:
                    rule += protocols_oc_to_xr[i.ipv4.config.protocol] + ' '
                else:
                    rule += 'ipv4' + ' '
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
                rules_oc_config.append((str(i.sequence_id), rule))
            for i in rules_oc_config:
                self.log.debug(f'{self.device_name} ACL {service_acl.name} ACE: {i}')
                r = acl.rule.create(i[0])
                r.line = i[1]

        if service_acl.type == 'oc-acl-ext:ACL_IPV4_STANDARD':
            raise ValueError('XR does not support ACL type oc-acl-ext:ACL_IPV4_STANDARD.')


def xr_acls_interfaces_program_service(self) -> None:
    """
    Program xr interfaces ingress and egress acls
    """
    for service_acl_interface in self.service.oc_acl__acl.interfaces.interface:
        # Get interface object
        interface_type, interface_number = get_interface_type_and_number(
            service_acl_interface.interface_ref.config.interface)
        if interface_type == 'Port_channel':
            interface_type = 'Bundle_Ether'
        class_attribute = getattr(self.root.devices.device[self.device_name].config.cisco_ios_xr__interface,
                                  interface_type)

        if service_acl_interface.interface_ref.config.subinterface == 0 or not service_acl_interface.interface_ref.config.subinterface:
            interface_cdb = class_attribute[interface_number]
        else:
            attribute1 = getattr(self.root.devices.device[self.device_name].config.cisco_ios_xr__interface,
                                 f'{interface_type}_subinterface')
            sub_interface = getattr(attribute1, interface_type)
            interface_cdb = sub_interface[f'{interface_number}.{service_acl_interface.interface_ref.config.subinterface}']

        # Apply ACLs  TODO add other ACL types
        if service_acl_interface.egress_acl_sets:
            for acl in service_acl_interface.egress_acl_sets.egress_acl_set:
                if acl.type == 'oc-acl:ACL_IPV4':
                    if not interface_cdb.ipv4.access_group.exists('egress'):
                        interface_cdb.ipv4.access_group.create('egress')
                    interface_cdb.ipv4.access_group['egress'].name = acl.set_name
                    self.log.info(
                        f'{self.device_name} ACL {acl.set_name} added to interface {service_acl_interface.id} egress')
                elif acl.type == 'oc-acl-ext:ACL_IPV4_STANDARD':
                    raise ValueError('XR does not support ACL type oc-acl-ext:ACL_IPV4_STANDARD.')

        if service_acl_interface.ingress_acl_sets:
            for acl in service_acl_interface.ingress_acl_sets.ingress_acl_set:
                if acl.type == 'oc-acl:ACL_IPV4':
                    if not interface_cdb.ipv4.access_group.exists('ingress'):
                        interface_cdb.ipv4.access_group.create('ingress')
                    interface_cdb.ipv4.access_group['ingress'].name = acl.set_name
                    self.log.info(f'{self.device_name} ACL {acl.set_name} added to interface {service_acl_interface.id} ingress')
                elif acl.type == 'oc-acl-ext:ACL_IPV4_STANDARD':
                    raise ValueError('XR does not support ACL type oc-acl-ext:ACL_IPV4_STANDARD.')


def xr_acls_lines_program_service(self) -> None:
    """
    Program xr lines ingress and egress acls. Uses default template to configure lines.
    """
    device = self.root.devices.device[self.device_name].config
    for service_line in self.service.oc_acl__acl.oc_acl_ext__lines.line:
        if 'vty ' in service_line.id.lower():
            matches = re.findall(r'[0-9]+', service_line.id)
            if len(matches) == 2:
                line_start = int(matches[0])
                if line_start > 0:
                    raise ValueError(f'XR VTY line configuration error. NSO-OC-Services XR uses the default line template which must start with line 0. You configured line {line_start}')
                line_end = int(matches[1])
                device.cisco_ios_xr__vty_pool.default.first_vty = 0
                device.cisco_ios_xr__vty_pool.default.last_vty = line_end
                if service_line.egress_acl_set:
                    device.cisco_ios_xr__line.default.access_class.egress = service_line.egress_acl_set
                if service_line.ingress_acl_sets.ingress_acl_set:
                    for service_ingress in service_line.ingress_acl_sets.ingress_acl_set:
                        device.cisco_ios_xr__line.default.access_class.ingress = service_ingress.ingress_acl_set_name
                        if service_ingress.config.vrf and service_ingress.config.vrf != 'global':
                            raise ValueError(
                                f'XR VTY line configuration error. NSO-OC-Services XR only supports VTY line access-groups on the global routing instance at this time. You configured VRF {service_ingress.config.vrf}.')
                        if service_ingress.config.vrf_also:
                            raise ValueError(
                                f'XR VTY line configuration error. NSO-OC-Services XR does not support vrf-also.')
            else:
                raise ValueError('line vty takes a start and an end line number range')


def xr_acls_ntp_program_service(self) -> None:
    """
    Apply NTP ACLs
    """
    device = self.root.devices.device[self.device_name].config
    if self.service.oc_acl__acl.oc_acl_ext__ntp.server.config.server_acl_set or self.service.oc_acl__acl.oc_acl_ext__ntp.peer.config.peer_acl_set:
        device.cisco_ios_xr__ntp.access_group.delete()

    # Serve
    if self.service.oc_acl__acl.oc_acl_ext__ntp.server.config.server_acl_set:
        serve = device.cisco_ios_xr__ntp.access_group.create(('ipv4', 'serve'))
        serve.name = self.service.oc_acl__acl.oc_acl_ext__ntp.server.config.server_acl_set

    # Peer
    if self.service.oc_acl__acl.oc_acl_ext__ntp.peer.config.peer_acl_set:
        peer = device.cisco_ios_xr__ntp.access_group.create(('ipv4', 'peer'))
        peer.name = self.service.oc_acl__acl.oc_acl_ext__ntp.peer.config.peer_acl_set
