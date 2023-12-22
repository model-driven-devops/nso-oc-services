# -*- mode: python; python-indent: 4 -*-
import copy
import ipaddress

from translation.common import get_interface_type_and_number
from translation.common import get_interface_type_number_and_subinterface
from translation.common import verify_ipv4
from translation.openconfig_xr.common import xr_system_get_interface_ip_address


# from translation.openconfig_xe.xr_bgp import xr_bgp_global_program_service
# from translation.openconfig_xe.xr_bgp import xr_bgp_neighbors_program_service
# from translation.openconfig_xe.xr_bgp import xr_bgp_peer_groups_program_service
# from translation.openconfig_xe.xr_bgp import xr_bgp_redistribution_program_service
# from translation.openconfig_xe.xr_ospf import xr_ospf_program_service
# from translation.openconfig_xe.xr_ospf import xr_ospf_redistribution_program_service


def xr_network_instances_program_service(self, nso_props) -> None:
    """
    Program service for xr NED features
    """
    service_table_connection_dict = {}
    instance_bgp_list = []

    for network_instance in nso_props.service.oc_netinst__network_instances.network_instance:
        xr_configure_vrfs(self, nso_props, network_instance)
        xr_configure_vlan_db(nso_props, network_instance)  # will raises error
        xr_reconcile_vrf_interfaces(self, nso_props, network_instance)
        xr_configure_mpls(self, nso_props, network_instance)
        # xr_configure_pim(nso_props, network_instance)
        # xr_configure_igmp(nso_props, network_instance)
        xr_configure_cgmp(self, nso_props, network_instance)  # will raise error
        xr_get_table_connections(network_instance, service_table_connection_dict)
        configure_bgp_list(self, nso_props, network_instance, instance_bgp_list)
    
    xr_configure_protocols(self, nso_props, service_table_connection_dict, instance_bgp_list)


def xr_configure_vrfs(self, nso_props, network_instance) -> None:
    """
    Ensure VRF with correct address families is on the device
    """
    if network_instance.config.type != 'oc-ni-types:DEFAULT_INSTANCE':
        # Get VRFs from device cdb
        vrfs_device_db = list()
        for v in nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list:
            vrfs_device_db.append(v.name)
        self.log.info(f'{nso_props.device_name} VRFs in device {nso_props.device_name} CDB: {vrfs_device_db}')

        # Create VRF in device
        if (network_instance.name not in vrfs_device_db) and (network_instance.config.type == 'oc-ni-types:L3VRF'):
            nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list.create(network_instance.name)

        # Get address families for VRF from incoming configs
        vrf_address_families_in_model_configs = list()
        for af in network_instance.config.enabled_address_families:
            vrf_address_families_in_model_configs.append(af)

        # Create/delete address family presence containers as needed
        if nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
            network_instance.name].address_family.ipv4.unicast.exists():
            if 'IPV4' not in vrf_address_families_in_model_configs:
                del nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
                    network_instance.name].address_family.ipv4.unicast
        elif 'IPV4' in vrf_address_families_in_model_configs:
            nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
                network_instance.name].address_family.ipv4.unicast.create()

        if nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
            network_instance.name].address_family.ipv6.unicast.exists():
            if 'IPV6' not in vrf_address_families_in_model_configs:
                del nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
                    network_instance.name].address_family.ipv6.unicast
        elif 'IPV6' in vrf_address_families_in_model_configs:
            nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
                network_instance.name].address_family.ipv6.unicast.create()

        # Add route distinguisher
        if network_instance.config.route_distinguisher:
            nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
                network_instance.name].rd = network_instance.config.route_distinguisher

        # # Add route targets and inter-instance-policies
        # # Configure inter-instance-policies
        # import_rts_policy = set()
        # if network_instance.inter_instance_policies.apply_policy.config.import_policy:
        #     if len(network_instance.inter_instance_policies.apply_policy.config.import_policy) == 1:
        #         import_policy = \
        #         network_instance.inter_instance_policies.apply_policy.config.import_policy.as_list()[0]
        #         nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
        #             network_instance.name].address_family.ipv4.unicast.cisco_ios_xr__import.ipv4.route_policy = import_policy
        #
        #         # collect the route-targets to be used in 'route-target import X' statements
        #         import_policy_service = nso_props.service.oc_rpol__routing_policy.policy_definitions.policy_definition[import_policy]
        #         extcommunity_lists = list()
        #         for service_statement in import_policy_service.statements.statement:
        #             if service_statement.conditions.oc_bgp_pol__bgp_conditions.config.ext_community_set:
        #                 extcommunity_lists.append(service_statement.conditions.oc_bgp_pol__bgp_conditions.config.ext_community_set)
        #         for ext_community_list_name in extcommunity_lists:
        #             ext_list = nso_props.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.ext_community_sets.ext_community_set[ext_community_list_name]
        #             for community in ext_list.config.ext_community_member:
        #                 import_rts_policy.add(community)
        #     else:
        #         raise ValueError('XR supports one route-map for VRF import policy.')
        # export_rts_policy = set()
        # if network_instance.inter_instance_policies.apply_policy.config.export_policy:
        #     if len(network_instance.inter_instance_policies.apply_policy.config.export_policy) == 1:
        #         export_policy = \
        #         network_instance.inter_instance_policies.apply_policy.config.export_policy.as_list()[0]
        #         nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
        #             network_instance.name].address_family.ipv4.unicast.export.route_policy = export_policy
        #
        #         # collect the route-targets to be used in 'route-target import X' statements
        #         export_policy_service = nso_props.service.oc_rpol__routing_policy.policy_definitions.policy_definition[export_policy]
        #         extcommunity_lists = list()
        #         for service_statement in export_policy_service.statements.statement:
        #             if service_statement.conditions.oc_bgp_pol__bgp_conditions.config.ext_community_set:
        #                 extcommunity_lists.append(service_statement.conditions.oc_bgp_pol__bgp_conditions.config.ext_community_set)
        #         for ext_community_list_name in extcommunity_lists:
        #             ext_list = nso_props.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.ext_community_sets.ext_community_set[ext_community_list_name]
        #             for community in ext_list.config.ext_community_member:
        #                 export_rts_policy.add(community)
        #     else:
        #         raise ValueError('XR supports one route-map for VRF export policy.')

        # # Get import route-targets from configuration route-target import and import policy
        # rt_import_config = set([rt for rt in network_instance.config.route_targets_import])
        # rt_import_config.update(import_rts_policy)
        # # Get export route-targets from configuration route-target export and export policy
        # rt_export_config = set([rt for rt in network_instance.config.route_targets_export])
        # rt_export_config.update(export_rts_policy)
        #
        # # Get import route-targets from the CDB
        # rt_import_cdb = set([rt for rt in nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
        #     network_instance.name].address_family.ipv4.unicast.cisco_ios_xr__import.route_target.
        #     address_list])
        # # Get export route-targets from the CDB
        # rt_export_cdb = set([rt for rt in nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
        #     network_instance.name].address_family.ipv4.unicast.export.route_target.address_list])
        #
        # # Find route targets to create in CDB
        # rt_import_to_cdb = rt_import_config.difference(rt_import_cdb)
        # rt_export_to_cdb = rt_export_config.difference(rt_export_cdb)
        #
        # # Add Route Targets to CDB
        # for rt in rt_import_to_cdb:
        #     nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
        #         network_instance.name].address_family.ipv4.unicast.cisco_ios_xr__import.route_target.address_list.create(rt)
        # for rt in rt_export_to_cdb:
        #     nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__vrf.vrf_list[
        #         network_instance.name].address_family.ipv4.unicast.export.route_target.address_list.create(rt)


def xr_configure_vlan_db(nso_props, network_instance) -> None:
    """
    Ensure VLANS are created in the VLAN DB
    """
    if len(network_instance.vlans.vlan) > 0:
        for service_vlan in network_instance.vlans.vlan:
            raise ValueError('XR does not support VLANs.')


def xr_reconcile_vrf_interfaces(self, nso_props, network_instance) -> None:
    """
    Ensure device interfaces are in appropriate VRFs
    """
    # interfaces in default route table are marked None, else their VRF name
    if network_instance.config.type == 'oc-ni-types:DEFAULT_INSTANCE':
        # Get interfaces from configs
        vrf_interfaces_in_model_configs = dict()
        for a in network_instance.interfaces.interface:
            vrf_interfaces_in_model_configs[a.id] = None
        self.log.info(
            f'{nso_props.device_name} Interfaces in VRF configuration: {vrf_interfaces_in_model_configs}')
    else:
        # Get interfaces from configs
        vrf_interfaces_in_model_configs = dict()
        for a in network_instance.interfaces.interface:
            vrf_interfaces_in_model_configs[a.id] = network_instance.name
        self.log.info(
            f'{nso_props.device_name} Interfaces in VRF configuration: {vrf_interfaces_in_model_configs}')

    # Get interfaces from CDB
    vrf_interfaces_in_cdb = xr_get_all_interfaces(nso_props)
    self.log.info(
        f'{nso_props.device_name} These are the interfaces VRFs from cdb: {vrf_interfaces_in_cdb}')

    # Assign interfaces to correct VRFs
    for i in vrf_interfaces_in_cdb:
        try:
            interface_type, interface_number = get_interface_type_number_and_subinterface(i[0])
            class_attribute = getattr(nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__interface,
                                        interface_type)
            interface = class_attribute[interface_number]

            if i[0] in vrf_interfaces_in_model_configs:
                config_vrf = vrf_interfaces_in_model_configs[i[0]]
                self.log.info(
                    f'{nso_props.device_name} Configuring VRF: {config_vrf}  {interface_type, interface_number}')
                interface.vrf = config_vrf
        except Exception as e:
            self.log.error(
                f'{nso_props.device_name} Failed to ensure VRF configs for interface {interface_type, interface_number}')
            self.log.info(f'{nso_props.device_name} interface vrf failure traceback: {e}')


def xr_configure_mpls(self, nso_props, network_instance) -> None:
    """
    Configures the mpls section of openconfig-network-instance
    """
    if network_instance.mpls.oc_netinst__global.config:
        if network_instance.mpls.oc_netinst__global.config.ttl_propagation is False:
            nso_props.root.devices.device[
                nso_props.device_name].config.cisco_ios_xr__mpls.ip_ttl_propagate.disable.create()
        elif network_instance.mpls.oc_netinst__global.config.ttl_propagation:
            if nso_props.root.devices.device[
                nso_props.device_name].config.cisco_ios_xr__mpls.ip_ttl_propagate.disable.exists():
                del nso_props.root.devices.device[
                    nso_props.device_name].config.cisco_ios_xr__mpls.ip_ttl_propagate.disable
    
    if network_instance.mpls.oc_netinst__global.interface_attributes.interface:
        for interface in network_instance.mpls.oc_netinst__global.interface_attributes.interface:
            if interface.config.mpls_enabled:
                # MPLS is enabled on XR interfaces
                pass
            elif interface.config.mpls_enabled is False:
                raise ValueError('XR does not support disabling MPLS forwarding on interfaces.')
    if network_instance.mpls.signaling_protocols:
        if network_instance.mpls.signaling_protocols.ldp:
            xr_configure_mpls_signaling_protocols_ldp(self, nso_props, network_instance)


def xr_configure_mpls_signaling_protocols_ldp(self, nso_props, service_network_instance) -> None:
    """
    Configures LDP
    """
    if service_network_instance.mpls.signaling_protocols.ldp.oc_netinst__global.config.lsr_id:
        nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__mpls.ldp.create()
        nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__mpls.ldp.router_id = service_network_instance.mpls.signaling_protocols.ldp.oc_netinst__global.config.lsr_id
    if service_network_instance.mpls.signaling_protocols.ldp.oc_netinst__global.graceful_restart.config.enabled:
        nso_props.root.devices.device[
            nso_props.device_name].config.cisco_ios_xr__mpls.ldp.graceful_restart.create()
    if service_network_instance.mpls.signaling_protocols.ldp.interface_attributes.config.hello_holdtime:
        nso_props.root.devices.device[
            nso_props.device_name].config.cisco_ios_xr__mpls.ldp.discovery.hello.holdtime = service_network_instance.mpls.signaling_protocols.ldp.interface_attributes.config.hello_holdtime
    if service_network_instance.mpls.signaling_protocols.ldp.interface_attributes.config.hello_interval:
        nso_props.root.devices.device[
            nso_props.device_name].config.cisco_ios_xr__mpls.ldp.discovery.hello.interval = service_network_instance.mpls.signaling_protocols.ldp.interface_attributes.config.hello_interval
    # TODO - add interfaces to OC LDP with individual hello and holdtimes, send to XR


def xr_get_table_connections(network_instance, service_table_connection_dict) -> None:
    """
    Build dictionary of network instances their protocols and desired redistribution.
    """
    if network_instance.table_connections.table_connection:
        network_instance_table_connections = {
            network_instance.config.name: {
                'type': network_instance.config.type,
                'destination_protocols': {
                    'BGP': [],
                    'OSPF': [],
                    'OSPF3': [],
                    'ISIS': []
                }
            }
        }
        for service_table_connection in network_instance.table_connections.table_connection:
            import_policy = None
            if service_table_connection.config.import_policy:
                if len(service_table_connection.config.import_policy) == 1:
                    import_policy = service_table_connection.config.import_policy.as_list()[0]
                else:
                    raise ValueError('XR supports one route-map per redistribution statement.')
            if service_table_connection.config.src_protocol_process_number:
                src_process_number = service_table_connection.config.src_protocol_process_number
            else:
                src_process_number = None
            if service_table_connection.config.dst_protocol_process_number:
                dst_process_number = service_table_connection.config.dst_protocol_process_number
            else:
                dst_process_number = None
            table_connection = {
                'src-protocol': service_table_connection.src_protocol,
                'src-protocol-process-number': src_process_number,
                'dst-protocol': service_table_connection.dst_protocol,
                'dst-protocol-process-number': dst_process_number,
                'disable-metric-propagation': service_table_connection.config.disable_metric_propagation,
                'address-family': service_table_connection.config.address_family,
                'import-policy': import_policy
            }
            if service_table_connection.dst_protocol == 'oc-pol-types:BGP':
                network_instance_table_connections[network_instance.config.name]['destination_protocols'][
                    'BGP'].append(copy.deepcopy(table_connection))
            elif service_table_connection.dst_protocol == 'oc-pol-types:OSPF':
                network_instance_table_connections[network_instance.config.name]['destination_protocols'][
                    'OSPF'].append(copy.deepcopy(table_connection))
            elif service_table_connection.dst_protocol == 'oc-pol-types:OSPF3':
                network_instance_table_connections[network_instance.config.name]['destination_protocols'][
                    'OSPF3'].append(copy.deepcopy(table_connection))
            elif service_table_connection.dst_protocol == 'oc-pol-types:ISIS':
                network_instance_table_connections[network_instance.config.name]['destination_protocols'][
                    'ISIS'].append(copy.deepcopy(table_connection))
        if network_instance_table_connections:
            service_table_connection_dict.update(copy.deepcopy(network_instance_table_connections))


def configure_bgp_list(self, nso_props, network_instance, instance_bgp_list):
    if network_instance.protocols.protocol:
        for p in network_instance.protocols.protocol:
            if p.identifier == 'oc-pol-types:STATIC':
                device_route = nso_props.root.devices.device[nso_props.device_name].config.cisco_ios_xr__router.static
                if network_instance.config.type == 'oc-ni-types:DEFAULT_INSTANCE':  # if global table
                    if p.static_routes.static:
                        for static in p.static_routes.static:
                            for nh in static.next_hops.next_hop:
                                configure_static_route_main(device_route, static, nh)
                elif network_instance.config.type == 'oc-ni-types:L3VRF':  # if VRF table
                    if not device_route.vrf.exists(network_instance.name):
                        device_route.vrf.create(network_instance.name)
                    if p.static_routes.static:
                        for static in p.static_routes.static:
                            route_vrf = device_route.vrf[network_instance.name]
                            for nh in static.next_hops.next_hop:
                                configure_static_route_main(route_vrf, static, nh)
            
            # Uncomment when xr_ospf is developed
            # if p.identifier == 'oc-pol-types:OSPF':
            #     xr_ospf_program_service(self, p, network_instance.config.type, network_instance.config.name)

            # oc-ni-types:DEFAULT_INSTANCE must be processed before VRFs
            # Incoming order doesn't matter
            # Collect needed BGP instance information below
            if p.identifier == 'oc-pol-types:BGP':
                instance_bgp_list.append((p, network_instance.config.type, network_instance.config.name))


def xr_configure_protocols(self, nso_props, table_connections: dict, instance_bgp_list: list) -> None:
    """
    Configures the protocols section of openconfig-network-instance
    """
    # Configure redistribution into OSPF
    # Uncomment when xr_ospf is developed
    # xr_ospf_redistribution_program_service(self, nso_props, table_connections)

    # Sort BGP instance information so oc-ni-types:DEFAULT_INSTANCE is first and process
    if instance_bgp_list:
        instance_bgp_list.sort(key=lambda x: x[1])
        self.log.info(f'{nso_props.device_name} instance_bgp_list {instance_bgp_list}')

        # Uncomment when xr_bgp is developed
        # for bgp_instance in instance_bgp_list:
            # xr_bgp_global_program_service(self, bgp_instance[0], bgp_instance[1], bgp_instance[2])
            # xr_bgp_peer_groups_program_service(self, bgp_instance[0], bgp_instance[1], bgp_instance[2])
            # xr_bgp_neighbors_program_service(self, bgp_instance[0], bgp_instance[1], bgp_instance[2])
            # xr_bgp_redistribution_program_service(self, bgp_instance[0], bgp_instance[1], bgp_instance[2], table_connections)


def xr_get_all_interfaces(nso_props) -> list:
    """
    Returns a list of tuples, e.g.  [('GigabitEthernet0/0/0/1', None), ('GigabitEthernet0/0/0/4', 'abc')]
    """
    interfaces = list()
    device_config = nso_props.root.devices.device[nso_props.device_name].config
    for a in dir(device_config.cisco_ios_xr__interface):
        if not a.startswith('__'):
            class_method = getattr(device_config.cisco_ios_xr__interface, a)
            for c in class_method:
                try:
                    p = c._keystr.replace("{", "").replace("}", "")
                    interfaces.append((str(c) + p, c.vrf))
                except:
                    pass
    return interfaces


def create_route_nh_interface(cdb_device_ip_route, service_static_route_object, service_next_hop_object,
                              cdb_route_next_hop) -> None:
    """
    Configures static routes with next-hop interface in global or VRF route tables
    :param cdb_device_ip_route:
    :param service_static_route_object:
    :param service_next_hop_object:
    :param cdb_route_next_hop:
    :return:
    """
    ipaddress_prefix = ipaddress.ip_network(service_static_route_object.prefix)
    route = cdb_device_ip_route.address_family.ipv4.unicast.routes_if.create(
        str(ipaddress_prefix.network_address) + '/' + str(ipaddress_prefix.prefixlen),
        cdb_route_next_hop)
    if service_next_hop_object.config.metric:
        route.metric = service_next_hop_object.config.metric
    if service_static_route_object.config.description:
        if cdb_route_next_hop == 'dhcp':
            raise ValueError('XR static routes do not support using DHCP as the next-hop.')
        else:
            route.description = service_static_route_object.config.description
    if service_static_route_object.config.set_tag:
        if cdb_route_next_hop == 'dhcp':
            raise ValueError('XR static routes do not support using DHCP as the next-hop.')
        else:
            route.tag = service_static_route_object.config.set_tag
    if service_next_hop_object.config.oc_loc_rt_ext__dhcp_learned == 'ENABLE':
        raise ValueError('XR static routes do not support using DHCP as the next-hop.')
    if service_next_hop_object.config.oc_loc_rt_ext__dhcp_learned == 'DISABLE':
        raise ValueError('XR static routes do not support using DHCP as the next-hop.')


def create_route_nh_interface_and_ip(cdb_device_ip_route, service_static_route_object,
                                     service_next_hop_object, cdb_route_next_hop,
                                     cdb_route_next_hop_ip) -> None:
    """
    Configures static routes with a next-hop interface and IP in global or VRF route tables
    :param cdb_device_ip_route:
    :param service_static_route_object:
    :param service_next_hop_object:
    :param cdb_route_next_hop:
    :param cdb_route_next_hop_ip:
    :return:
    """
    ipaddress_prefix = ipaddress.ip_network(service_static_route_object.prefix)
    route = cdb_device_ip_route.address_family.ipv4.unicast.routes.create(
        str(ipaddress_prefix.network_address) + '/' + str(ipaddress_prefix.prefixlen),
        cdb_route_next_hop,
        cdb_route_next_hop_ip)
    if service_next_hop_object.config.metric:
        route.metric = service_next_hop_object.config.metric
    if service_static_route_object.config.description:
        route.description = service_static_route_object.config.description
    if service_static_route_object.config.set_tag:
        route.tag = service_static_route_object.config.set_tag


def create_route_nh_ip(cdb_device_ip_route, service_static_route_object, service_next_hop_object) -> None:
    """
    Configures static routes with an IP next-hop in global or VRF route tables
    :param cdb_device_ip_route:
    :param service_static_route_object:
    :param service_next_hop_object:
    :return:
    """
    ipaddress_prefix = ipaddress.ip_network(service_static_route_object.prefix)
    route = cdb_device_ip_route.address_family.ipv4.unicast.routes_ip.create(
        str(ipaddress_prefix.network_address) + '/' + str(ipaddress_prefix.prefixlen),
        service_next_hop_object.config.next_hop)
    if service_next_hop_object.config.metric:
        route.metric = service_next_hop_object.config.metric
    if service_static_route_object.config.description:
        route.description = service_static_route_object.config.description
    if service_static_route_object.config.set_tag:
        route.tag = service_static_route_object.config.set_tag
    if hasattr(service_next_hop_object.config, 'oc_loc_rt_ext__global'):
        if service_next_hop_object.config.oc_loc_rt_ext__global:
            raise ValueError('XR static routes do not support using the global keyword. Use RPL instead')


def configure_static_route_main(cdb_ip_route, static, nh) -> None:
    """
    Configure static routes
    :param cdb_ip_route:
    :param static:
    :param nh:
    :return:
    """
    if verify_ipv4(nh.config.next_hop) and not nh.interface_ref.config.interface:
        create_route_nh_ip(cdb_ip_route, static, nh)
    elif verify_ipv4(nh.config.next_hop) and nh.interface_ref.config.interface:
        if not nh.interface_ref.config.subinterface or nh.interface_ref.config.subinterface == 0:
            next_hop_interface = nh.interface_ref.config.interface
        else:
            next_hop_interface = f'{nh.interface_ref.config.interface}.{str(nh.interface_ref.config.subinterface)}'
        create_route_nh_interface_and_ip(cdb_ip_route, static, nh, next_hop_interface, nh.config.next_hop)
    elif nh.config.next_hop == 'oc-loc-rt-ext:DHCP':
        raise ValueError('XR static routes do not support using DHCP as the next-hop.')
    elif nh.config.next_hop == 'oc-loc-rt:DROP':
        create_route_nh_interface(cdb_ip_route, static, nh, 'Null0')
    elif nh.config.next_hop == 'oc-loc-rt:LOCAL_LINK' or not nh.config.next_hop:
        if not nh.interface_ref.config.subinterface or nh.interface_ref.config.subinterface == 0:
            next_hop_interface = nh.interface_ref.config.interface
        else:
            next_hop_interface = f'{nh.interface_ref.config.interface}.{str(nh.interface_ref.config.subinterface)}'
        create_route_nh_interface(cdb_ip_route, static, nh, next_hop_interface)
    else:
        raise ValueError('Unsupported static route configuration.')


# def xr_configure_pim(nso_props, network_instance) -> None:
#     """
#     Configures the pim section of openconfig-network-instance
#     """
#     #  TODO
#     if network_instance.protocols.protocol:
#         for p in network_instance.protocols.protocol:
#             if p.identifier == 'oc-pol-types:PIM':
#                 if p.config.enabled == True:
#                     if nso_props.root.devices.device[nso_props.device_name].config.ios__ip.multicast_routing.distributed.exists() == False:
#                         nso_props.root.devices.device[nso_props.device_name].config.ios__ip.multicast_routing.distributed.create()
#                 elif p.config.enabled == False:
#                     if nso_props.root.devices.device[nso_props.device_name].config.ios__ip.multicast_routing.distributed.exists() == True:
#                         nso_props.root.devices.device[nso_props.device_name].config.ios__ip.multicast_routing.distributed.delete()
#                 for iid in p.pim.interfaces.interface:
#                     interface_type, interface_number = get_interface_type_and_number(iid.interface_ref.config.interface)
#                     class_attribute = getattr(nso_props.root.devices.device[nso_props.device_name].config.ios__interface, interface_type)
#                     if iid.interface_ref.config.subinterface == 0:
#                         interface_cdb = class_attribute[interface_number]
#                     else:
#                         interface_cdb = class_attribute[f'{interface_number}.{iid.interface_ref.config.subinterface}']
#                     if iid.config.enabled == True:
#                         if iid.config.mode == 'oc-pim-types:PIM_MODE_SPARSE':
#                             interface_cdb.ip.pim.mode = 'sparse-mode'
#                         elif iid.config.mode == 'oc-pim-types:PIM_MODE_DENSE':
#                             interface_cdb.ip.pim.mode = 'sparse-dense-mode'
#                         interface_cdb.ip.pim.dr_priority = iid.config.dr_priority
#                         interface_cdb.ip.pim.query_interval = iid.config.hello_interval
#                         interface_cdb.ip.pim.neighbor_filter = iid.config.neighbor_filter
#                     elif iid.config.enabled == False:
#                         interface_cdb.ip.pim.delete()
#
#
# def xr_configure_igmp(nso_props, network_instance) -> None:
#     """
#     Configures the igmp section of openconfig-network-instance
#     """
#     # TODO
#     if network_instance.protocols.protocol:
#         for p in network_instance.protocols.protocol:
#             if p.identifier == 'oc-pol-types:IGMP':
#                 for iid in p.igmp.interfaces.interface:
#                     interface_type, interface_number = get_interface_type_and_number(iid.interface_ref.config.interface)
#                     class_attribute = getattr(nso_props.root.devices.device[nso_props.device_name].config.ios__interface, interface_type)
#                     if iid.interface_ref.config.subinterface == 0:
#                         interface_cdb = class_attribute[interface_number]
#                     else:
#                         interface_cdb = class_attribute[f'{interface_number}.{iid.interface_ref.config.subinterface}']
#                     if iid.config.enabled == True:
#                         interface_cdb.ip.igmp.version = iid.config.version
#                         interface_cdb.ip.igmp.query_interval = iid.config.query_interval
#                         interface_cdb.ip.igmp.access_group = iid.config.filter_prefixes
#                     elif iid.config.enabled == False:
#                         interface_cdb.ip.igmp.delete()


def xr_configure_cgmp(self, nso_props, network_instance) -> None:
    """
    Configures the cgmp section of openconfig-network-instance
    """
    if network_instance.protocols.protocol:
        for p in network_instance.protocols.protocol:
            if p.identifier == 'oc-pol-types:CGMP':
                raise ValueError('XR does not support CGMP.')