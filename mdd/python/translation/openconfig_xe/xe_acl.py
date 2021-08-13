# -*- mode: python; python-indent: 4 -*-
import ipaddress


def prefix_to_network_and_mask(prefix: str) -> str:
    """
    Turns a network prefix into a network_id and wildcard-mask
    :param prefix: str
    :return: 'network_id wildcard_mask': str
    """
    network = ipaddress.ip_network(prefix)
    return f'{str(network.network_address)} {str(network.hostmask)}'


def xe_acl_program_service(self):
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

    if self.service.type == 'oc-acl:ACL_IPV4':
        device = self.root.devices.device[self.device_name].config
        if not device.ios__ip.access_list.extended.ext_named_acl.exists(self.service.name):
            device.ios__ip.access_list.extended.ext_named_acl.create(self.service.name)

        acl = device.ios__ip.access_list.extended.ext_named_acl[self.service.name]
        rules_oc_config = list()  # {"10 permit tcp any 1.1.1.1 0.0.0.0 eq 80"}'
        for i in self.service.acl_entries.acl_entry:
            rule = str(i.sequence_id) + ' ' + actions_oc_to_xe[i.actions.config.forwarding_action] + ' '
            if i.ipv4.config.protocol:
                rule += protocols_oc_to_xe[i.ipv4.config.protocol] + ' '
            else:
                rule += 'ip' + ' '
            if i.ipv4.config.source_address == '0.0.0.0/0':
                rule += 'any '
            else:
                rule += prefix_to_network_and_mask(i.ipv4.config.source_address) + ' '
            if i.ipv4.config.protocol == 'IP_TCP' or i.ipv4.config.protocol == 'IP_UDP':
                if i.transport.config.source_port :
                    if i.transport.config.source_port == 'ANY':
                        pass
                    else:
                        rule += 'eq ' + i.transport.config.source_port + ' '
            if i.ipv4.config.destination_address == '0.0.0.0/0':
                rule += 'any '
            else:
                rule += prefix_to_network_and_mask(i.ipv4.config.destination_address) + ' '
            if i.ipv4.config.protocol == 'IP_TCP' or i.ipv4.config.protocol == 'IP_UDP':
                if i.transport.config.destination_port:
                    if i.transport.config.destination_port == 'ANY':
                        pass
                    else:
                        rule += 'eq ' + i.transport.config.destination_port + ' '
            rules_oc_config.append(rule)
        for i in rules_oc_config:
            self.log.info(f'{self.device_name} ACL {self.service.name} ACE: {i}')
            acl.ext_access_list_rule.create(i)
