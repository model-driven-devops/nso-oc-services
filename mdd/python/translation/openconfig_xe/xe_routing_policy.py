# -*- mode: python; python-indent: 4 -*-
import re

regex_ipv4_masklength_range = re.compile(r'([0-9]{1,2})\.\.([0-9]{1,2})')


def xe_routing_policy_program_service(self) -> None:
    if len(self.service.oc_rpol__routing_policy.defined_sets.prefix_sets.prefix_set) > 0:
        prefix_sets_configure(self)
    if len(self.service.oc_rpol__routing_policy.defined_sets.bgp_defined_sets.as_path_sets.as_path_set) > 0:
        as_path_sets_configure(self)
    if len(self.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.community_sets.community_set) > 0:
        community_sets_configure(self)


def prefix_sets_configure(self) -> None:
    device = self.root.devices.device[self.device_name].config
    for service_prefix_set in self.service.oc_rpol__routing_policy.defined_sets.prefix_sets.prefix_set:
        if service_prefix_set.config.mode == 'IPV4':
            if not device.ios__ip.prefix_list.prefixes.exists(service_prefix_set.config.name):
                device.ios__ip.prefix_list.prefixes.create(service_prefix_set.config.name)

            prefix_list_cdb = device.ios__ip.prefix_list.prefixes[service_prefix_set.config.name]

            for service_prefix in service_prefix_set.prefixes.prefix:
                if service_prefix.config.masklength_range.lower() == 'exact':
                    statement = prefix_list_cdb.seq.create(service_prefix.config.seq)
                    statement.permit.ip = service_prefix.config.ip_prefix
                else:
                    result = regex_ipv4_masklength_range.match(service_prefix.config.masklength_range)
                    ml = [int(result.group(1)), int(result.group(2))]
                    ml.sort()
                    statement = prefix_list_cdb.seq.create(service_prefix.config.seq)
                    statement.permit.ip = service_prefix.config.ip_prefix
                    statement.permit.ge = ml[0]
                    statement.permit.le = ml[1]


def as_path_sets_configure(self) -> None:
    device = self.root.devices.device[self.device_name].config
    for service_as_path_set in self.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.as_path_sets.as_path_set:
        if not device.ios__ip.as_path.access_list.exists(service_as_path_set.config.as_path_set_name):
            device.ios__ip.as_path.access_list.create(service_as_path_set.config.as_path_set_name)

        as_path_list_cdb = device.ios__ip.as_path.access_list[service_as_path_set.config.as_path_set_name]

        for as_path_member in service_as_path_set.config.as_path_set_member:
            as_path_list_cdb.as_path_rule.create(('permit', as_path_member))


def community_sets_configure(self) -> None:
    device = self.root.devices.device[self.device_name].config

    # Always use ip bgp-community new-format
    if not device.ios__ip.bgp_community.new_format.exists():
        device.ios__ip.bgp_community.new_format.create()

    for service_community_set in self.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.community_sets.community_set:
        if not device.ios__ip.community_list.standard.exists(service_community_set.config.community_set_name):
            device.ios__ip.community_list.standard.create(service_community_set.config.community_set_name)

        community_list_cdb = device.ios__ip.community_list.standard[service_community_set.config.community_set_name]

        for community_member in service_community_set.config.community_member:
            community_list_cdb.entry.create(f'permit {community_member}')
