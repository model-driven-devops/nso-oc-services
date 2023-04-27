# -*- mode: python; python-indent: 4 -*-
import re
import copy

regex_ipv4_masklength_range = re.compile(r'([0-9]{1,2})\.\.([0-9]{1,2})')
regex_meta = {'[', '\\', '.', '^', '$', '*', '+', '?', '{', '|', '('}


def xe_routing_policy_program_service(self, nso_props) -> None:
    if len(nso_props.service.oc_rpol__routing_policy.defined_sets.prefix_sets.prefix_set) > 0:
        prefix_sets_configure(nso_props)
    if len(nso_props.service.oc_rpol__routing_policy.defined_sets.bgp_defined_sets.as_path_sets.as_path_set) > 0:
        as_path_sets_configure(nso_props)
    if len(nso_props.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.community_sets.community_set) > 0:
        community_sets_configure(nso_props)
    if len(nso_props.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.ext_community_sets.ext_community_set) > 0:
        ext_community_sets_configure(nso_props)
    if len(nso_props.service.oc_rpol__routing_policy.policy_definitions.policy_definition) > 0:
        policy_definitions_configure(nso_props)


def policy_definitions_configure(nso_props) -> None:
    device = nso_props.root.devices.device[nso_props.device_name].config
    for service_policy_definition in nso_props.service.oc_rpol__routing_policy.policy_definitions.policy_definition:
        if len(service_policy_definition.statements.statement) > 0:
            for service_policy_statement in service_policy_definition.statements.statement:
                route_map_statement = device.ios__route_map.create(service_policy_definition.name, service_policy_statement.name)
                if service_policy_statement.actions:
                    if service_policy_statement.actions.config.policy_result == 'ACCEPT_ROUTE':
                        route_map_statement.operation = 'permit'
                    elif service_policy_statement.actions.config.policy_result == 'REJECT_ROUTE':
                        route_map_statement.operation = 'deny'
                    if service_policy_statement.actions.set_tag:
                        if service_policy_statement.actions.set_tag.config.mode == 'INLINE':
                            route_map_statement.set.tag = service_policy_statement.actions.set_tag.inline.config.tag.as_list()[0]
                    if service_policy_statement.actions.oc_bgp_pol__bgp_actions:
                        if service_policy_statement.actions.oc_bgp_pol__bgp_actions.config:
                            if service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_route_origin:
                                if service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_route_origin == 'IGP' or service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_route_origin == 'INCOMPLETE':
                                    route_map_statement.set.origin.origin_value = str(service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_route_origin).lower()
                                elif service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_route_origin == 'EGP':  # TODO find way to add ASN and allow EGP
                                    raise ValueError(
                                        'OpenConfig model does not allow for ASN which is needed for an EGP originated route')
                            if service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_local_pref:
                                lp = route_map_statement.set.local_preference.create()
                                lp.value = service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_local_pref
                            if service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_next_hop:
                                if service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_next_hop == 'SELF':
                                    route_map_statement.set.ip.next_hop.self.create()
                                else:
                                    if route_map_statement.set.ip.next_hop.self.exists():
                                        route_map_statement.set.ip.next_hop.self.delete()
                                    route_map_statement.set.ip.next_hop.address.create(service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_next_hop)
                            if service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_med:
                                route_map_statement.set.metric = [service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_med]
                            if service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_weight:
                                route_map_statement.set.weight = service_policy_statement.actions.oc_bgp_pol__bgp_actions.config.set_weight
                            if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_as_path_prepend:
                                if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_as_path_prepend.config.repeat_n:
                                    as_path = ((str(service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_as_path_prepend.config.asn) + ' ') * service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_as_path_prepend.config.repeat_n).strip()
                                    route_map_statement.set.as_path.prepend.as_list = as_path
                                else:
                                    route_map_statement.set.as_path.prepend.as_list = service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_as_path_prepend.config.asn
                            if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_community:
                                if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_community.config.options == 'ADD':
                                    if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_community.config.method == 'INLINE':
                                        for community in service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_community.inline.config.communities:
                                            route_map_statement.set.community.community_number.create(community)
                                        route_map_statement.set.community.community_number.create('additive')
                                elif service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_community.config.options == 'REPLACE':
                                    if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_community.config.method == 'INLINE':
                                        route_map_statement.set.community.community_number = service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_community.inline.config.communities.as_list()
                                elif service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_community.config.options == 'REMOVE':
                                    if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_community.config.method == 'REFERENCE':
                                        route_map_statement.set.comm_list.name = service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_community.reference.config.community_set_ref
                                        route_map_statement.set.comm_list['delete'].create()
                            if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_ext_community:
                                if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_ext_community.config.options == 'ADD':
                                    if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_ext_community.config.method == 'INLINE':
                                        for community in service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_ext_community.inline.config.communities:
                                            route_map_statement.set.extcommunity.rt.create(community)
                                        route_map_statement.set.extcommunity.rt.create('additive')
                                elif service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_ext_community.config.options == 'REPLACE':
                                    if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_ext_community.config.method == 'INLINE':
                                        route_map_statement.set.extcommunity.rt = service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_ext_community.inline.config.communities.as_list()
                                elif service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_ext_community.config.options == 'REMOVE':
                                    if service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_ext_community.config.method == 'REFERENCE':
                                        route_map_statement.set.extcomm_list.name = service_policy_statement.actions.oc_bgp_pol__bgp_actions.set_ext_community.reference.config.ext_community_set_ref
                                        route_map_statement.set.extcomm_list['delete'].create()

                if service_policy_statement.conditions:
                    if service_policy_statement.conditions.match_prefix_set.config.prefix_set:
                        route_map_statement.match.ip.address.prefix_list.create(service_policy_statement.conditions.match_prefix_set.config.prefix_set)
                    if service_policy_statement.conditions.match_tag_set.config.tag_set:
                        tag_list_name = service_policy_statement.conditions.match_tag_set.config.tag_set
                        tag_list_element = nso_props.service.oc_rpol__routing_policy.defined_sets.tag_sets.tag_set[tag_list_name]
                        if len(tag_list_element.config.tag_value.as_list()) == 1:
                            route_map_statement.match.tag = [tag_list_element.config.tag_value.as_list()[0]]
                        else:
                            raise ValueError('XE route map match statements can only match a tag-set consisting of one value')
                    if service_policy_statement.conditions.oc_bgp_pol__bgp_conditions:
                        if service_policy_statement.conditions.oc_bgp_pol__bgp_conditions.match_as_path_set.config.as_path_set:
                            route_map_statement.match.as_path = [service_policy_statement.conditions.oc_bgp_pol__bgp_conditions.match_as_path_set.config.as_path_set]
                        if service_policy_statement.conditions.oc_bgp_pol__bgp_conditions.config.community_set:
                            route_map_statement.match.community = [service_policy_statement.conditions.oc_bgp_pol__bgp_conditions.config.community_set]
                        if service_policy_statement.conditions.oc_bgp_pol__bgp_conditions.config.ext_community_set:
                            route_map_statement.match.extcommunity = [service_policy_statement.conditions.oc_bgp_pol__bgp_conditions.config.ext_community_set]
                    if service_policy_statement.conditions.oc_routing_policy_ext__match_acl_ipv4_set.config.acl_set:
                        route_map_statement.match.ip.address.access_list = [service_policy_statement.conditions.oc_routing_policy_ext__match_acl_ipv4_set.config.acl_set]


def prefix_sets_configure(nso_props) -> None:
    device = nso_props.root.devices.device[nso_props.device_name].config
    for service_prefix_set in nso_props.service.oc_rpol__routing_policy.defined_sets.prefix_sets.prefix_set:
        if service_prefix_set.config.mode == 'IPV4':
            if not device.ios__ip.prefix_list.prefixes.exists(service_prefix_set.config.name):
                device.ios__ip.prefix_list.prefixes.create(service_prefix_set.config.name)

            prefix_list_cdb = device.ios__ip.prefix_list.prefixes[service_prefix_set.config.name]

            for service_prefix in service_prefix_set.prefixes.prefix:
                if service_prefix.config.masklength_range.lower() == 'exact':
                    statement = prefix_list_cdb.seq.create(service_prefix.config.seq)
                    if service_prefix.config.policy_action == 'DENY_ROUTE':
                        statement.deny.ip = service_prefix.config.ip_prefix
                    else:
                        statement.permit.ip = service_prefix.config.ip_prefix
                else:
                    result = regex_ipv4_masklength_range.match(service_prefix.config.masklength_range)
                    ml = [int(result.group(1)), int(result.group(2))]
                    ml.sort()
                    statement = prefix_list_cdb.seq.create(service_prefix.config.seq)
                    if service_prefix.config.policy_action == 'DENY_ROUTE':
                        statement.deny.ip = service_prefix.config.ip_prefix
                        if ml[0] > 0:  # if ge == 0; shouldn't add to statement
                            statement.deny.ge = ml[0]
                        statement.deny.le = ml[1]
                    else:
                        statement.permit.ip = service_prefix.config.ip_prefix
                        if ml[0] > 0:  # if ge == 0; shouldn't add to statement
                            statement.permit.ge = ml[0]
                        statement.permit.le = ml[1]


def as_path_sets_configure(nso_props) -> None:
    device = nso_props.root.devices.device[nso_props.device_name].config
    for service_as_path_set in nso_props.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.as_path_sets.as_path_set:
        if not device.ios__ip.as_path.access_list.exists(service_as_path_set.config.as_path_set_name):
            device.ios__ip.as_path.access_list.create(service_as_path_set.config.as_path_set_name)

        as_path_list_cdb = device.ios__ip.as_path.access_list[service_as_path_set.config.as_path_set_name]

        for as_path_member in service_as_path_set.config.as_path_set_member:
            as_path_list_cdb.as_path_rule.create(('permit', as_path_member))


def community_sets_configure(nso_props) -> None:
    device = nso_props.root.devices.device[nso_props.device_name].config
    # Always use ip bgp-community new-format
    if not device.ios__ip.bgp_community.new_format.exists():
        device.ios__ip.bgp_community.new_format.create()

    requested_community_lists = list()
    for service_community_set in nso_props.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.community_sets.community_set:
        temp_dict = {'name': service_community_set.config.community_set_name,
                     'match-set-options': service_community_set.config.match_set_options,
                     'list_type': 'standard',
                     'communities': []}
        for community in service_community_set.config.community_member:
            if set(community) & regex_meta:  # check intersection of regex characters and community string
                temp_dict['list_type'] = 'expanded'
            if community == 'NO_EXPORT':
                temp_dict['communities'].append('no-export')
            elif community == 'NO_ADVERTISE':
                temp_dict['communities'].append('no-advertise')
            elif community == 'NO_EXPORT_SUBCONFED':
                temp_dict['communities'].append('local-as')
            elif community == 'NOPEER':
                raise ValueError('OC BGP COMMUNITY NOPEER is not supported in Cisco IOS XE')
            else:
                temp_dict['communities'].append(community)
        requested_community_lists.append(copy.deepcopy(temp_dict))

    for request in requested_community_lists:
        if request['list_type'] == 'standard':
            if not device.ios__ip.community_list.standard.exists(request['name']):
                device.ios__ip.community_list.standard.create(request['name'])
            community_list_cdb = device.ios__ip.community_list.standard[request['name']]
            for community_member in request['communities']:
                community_list_cdb.entry.create(f'permit {community_member}')

        elif request['list_type'] == 'expanded':
            if not device.ios__ip.community_list.expanded.exists(request['name']):
                device.ios__ip.community_list.expanded.create(request['name'])
            community_list_cdb = device.ios__ip.community_list.expanded[request['name']]
            for community_member in request['communities']:
                community_list_cdb.entry.create(f'permit {community_member}')


def ext_community_sets_configure(nso_props) -> None:
    device = nso_props.root.devices.device[nso_props.device_name].config
    # Always use ip bgp-community new-format
    if not device.ios__ip.bgp_community.new_format.exists():
        device.ios__ip.bgp_community.new_format.create()

    for service_ext_community_set in nso_props.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.ext_community_sets.ext_community_set:
        ext_community_list = list()
        for community in service_ext_community_set.config.ext_community_member:
            ext_community_list.append(community)

        if not device.ios__ip.extcommunity_list.standard.no_mode_list.exists(service_ext_community_set.config.ext_community_set_name):
            device.ios__ip.extcommunity_list.standard.no_mode_list.create(service_ext_community_set.config.ext_community_set_name)
        ext_community_list_cdb = device.ios__ip.extcommunity_list.standard.no_mode_list[service_ext_community_set.config.ext_community_set_name]

        command = 'permit '
        for cm in ext_community_list:
            command += f'rt {cm} '
        ext_community_list_cdb.entry.create(command.strip())
