# -*- mode: python; python-indent: 4 -*-
from translation.openconfig_xe.common import xe_get_interface_type_and_number


def xe_bgp_global_program_service(self, service_protocol, network_instance_type, vrf_name) -> None:
    """
    Program service for xe NED features
    """
    self.log.info(f'{self.device_name} BGP global')
    service_bgp_global = service_protocol.bgp.oc_netinst__global

    if network_instance_type == 'oc-ni-types:DEFAULT_INSTANCE':
        if not self.root.devices.device[self.device_name].config.ios__router.bgp.exists(
                service_bgp_global.config.oc_netinst__as):
            self.root.devices.device[self.device_name].config.ios__router.bgp.create(
                service_bgp_global.config.oc_netinst__as)
        device_bgp_cbd = self.root.devices.device[self.device_name].config.ios__router.bgp[
            service_bgp_global.config.oc_netinst__as]
        if service_bgp_global.config.router_id:
            device_bgp_cbd.bgp.router_id = service_bgp_global.config.router_id
        if service_bgp_global.default_route_distance.config.external_route_distance and service_bgp_global.default_route_distance.config.internal_route_distance:  # because command needs ex, in, and local
            device_bgp_cbd.distance.bgp.extern_as = service_bgp_global.default_route_distance.config.external_route_distance
            device_bgp_cbd.distance.bgp.internal_as = service_bgp_global.default_route_distance.config.internal_route_distance
            device_bgp_cbd.distance.bgp.local = '200'  # TODO add this to extensions

        if service_bgp_global.graceful_restart:
            if service_bgp_global.graceful_restart.config.enabled:
                if not device_bgp_cbd.bgp.graceful_restart.exists():
                    device_bgp_cbd.bgp.graceful_restart.create()
                if service_bgp_global.graceful_restart.config.restart_time:
                    device_bgp_cbd.bgp.graceful_restart_conf.graceful_restart.restart_time = service_bgp_global.graceful_restart.config.restart_time
                if service_bgp_global.graceful_restart.config.stale_routes_time:
                    device_bgp_cbd.bgp.graceful_restart_conf.graceful_restart.stalepath_time = int(
                        float(service_bgp_global.graceful_restart.config.stale_routes_time))

        if service_bgp_global.route_selection_options:
            if service_bgp_global.route_selection_options.config.always_compare_med:
                if not device_bgp_cbd.bgp.always_compare_med.exists():
                    device_bgp_cbd.bgp.always_compare_med.create()
            if service_bgp_global.route_selection_options.config.external_compare_router_id:
                if not device_bgp_cbd.bgp.bestpath.compare_routerid.exists():
                    device_bgp_cbd.bgp.bestpath.compare_routerid.create()

        if service_bgp_global.use_multiple_paths:
            if service_bgp_global.use_multiple_paths.config.enabled:
                if service_bgp_global.use_multiple_paths.ebgp.config.maximum_paths:
                    device_bgp_cbd.maximum_paths.paths.number_of_paths = service_bgp_global.use_multiple_paths.ebgp.config.maximum_paths
                if service_bgp_global.use_multiple_paths.ebgp.config.allow_multiple_as:
                    if not device_bgp_cbd.bgp.bestpath.as_path.multipath_relax.exists():
                        device_bgp_cbd.bgp.bestpath.as_path.multipath_relax.create()
                if service_bgp_global.use_multiple_paths.ibgp.config.maximum_paths:
                    device_bgp_cbd.maximum_paths.ibgp.paths.number_of_paths = service_bgp_global.use_multiple_paths.ibgp.config.maximum_paths

    device_bgp_cbd = self.root.devices.device[self.device_name].config.ios__router.bgp[
        service_bgp_global.config.oc_netinst__as]
    if service_bgp_global.afi_safis.afi_safi:
        device_bgp_cbd.bgp.default.ipv4_unicast = False  # If using AFI_SAFI turn off BGP ipv4 default
        for afi_safi_service in service_bgp_global.afi_safis.afi_safi:
            if network_instance_type == 'oc-ni-types:DEFAULT_INSTANCE' and afi_safi_service.config.enabled:
                if afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV4_UNICAST':
                    if not device_bgp_cbd.address_family.ipv4.exists('unicast'):
                        device_bgp_cbd.address_family.ipv4.create('unicast')
                elif afi_safi_service.config.afi_safi_name == 'oc-bgp-types:L3VPN_IPV4_UNICAST':
                    if not device_bgp_cbd.address_family.vpnv4.exists('unicast'):
                        device_bgp_cbd.address_family.vpnv4.create('unicast')
                elif afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV6_UNICAST':  # TODO
                    pass
                elif afi_safi_service.config.afi_safi_name == 'oc-bgp-types:L3VPN_IPV6_UNICAST':  # TODO
                    pass
            elif network_instance_type == 'oc-ni-types:L3VRF' and afi_safi_service.config.enabled:
                if afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV4_UNICAST' or \
                        afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV4_LABELED_UNICAST':
                    if not device_bgp_cbd.address_family.with_vrf.ipv4.exists('unicast'):
                        device_bgp_cbd.address_family.with_vrf.ipv4.create('unicast')
                    if not device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf.exists(vrf_name):
                        device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf.create(vrf_name)
                elif afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV6_UNICAST':  # TODO
                    pass


def xe_bgp_redistribution_program_service(self, service_protocol, network_instance_type, vrf_name,
                                          table_connections) -> None:
    """
    Program service for xe NED features
    """
    self.log.info(f'{self.device_name} BGP redistribution')
    if table_connections.get(vrf_name):
        if table_connections[vrf_name]['destination_protocols']['BGP']:
            device_bgp_cbd = self.root.devices.device[self.device_name].config.ios__router.bgp[
                service_protocol.bgp.oc_netinst__global.config.oc_netinst__as]
            for protocol in table_connections[vrf_name]['destination_protocols']['BGP']:
                if protocol['src-protocol'] == 'oc-pol-types:OSPF' and protocol['address-family'] == 'oc-types:IPV4':
                    if service_protocol.bgp.oc_netinst__global.afi_safis.afi_safi:
                        if network_instance_type == 'oc-ni-types:DEFAULT_INSTANCE':  # address-family ipv4 unicast
                            device_bgp_cbd.address_family.ipv4['unicast'].redistribute.ospf.create(protocol['src-protocol-process-number'])
                            if protocol['import-policy']:
                                device_bgp_cbd.address_family.ipv4['unicast'].redistribute.ospf[protocol['src-protocol-process-number']].route_map = protocol[
                                    'import-policy']
                        elif network_instance_type == 'oc-ni-types:L3VRF':  # address-family ipv4 unicast vrf
                            device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf[
                                vrf_name].redistribute.ospf.create(protocol['src-protocol-process-number'])
                            if protocol['import-policy']:
                                device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf[
                                    vrf_name].redistribute.ospf[protocol['src-protocol-process-number']].route_map = protocol['import-policy']
                    else:  # router ospf X
                        self.log.info(f" \n protocol['src-protocol-process-number'] \n {protocol['src-protocol-process-number']}")
                        device_bgp_cbd.redistribute.ospf.create(protocol['src-protocol-process-number'])
                        if protocol['import-policy']:
                            device_bgp_cbd.redistribute.ospf[protocol['src-protocol-process-number']].route_map = protocol['import-policy']
                elif protocol['src-protocol'] == 'oc-pol-types:OSPF3' and protocol['address-family'] == 'oc-types:IPV4':
                    pass
                elif protocol['src-protocol'] == 'oc-pol-types:STATIC' and protocol['address-family'] == 'oc-types:IPV4':
                    if service_protocol.bgp.oc_netinst__global.afi_safis.afi_safi:
                        if network_instance_type == 'oc-ni-types:DEFAULT_INSTANCE':  # address-family ipv4 unicast
                            device_bgp_cbd.address_family.ipv4['unicast'].redistribute.static.create()
                            if protocol['import-policy']:
                                device_bgp_cbd.address_family.ipv4['unicast'].redistribute.static.route_map = protocol[
                                    'import-policy']
                        elif network_instance_type == 'oc-ni-types:L3VRF':  # address-family ipv4 unicast vrf
                            device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf[
                                vrf_name].redistribute.static.create()
                            if protocol['import-policy']:
                                device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf[
                                    vrf_name].redistribute.static.route_map = protocol['import-policy']
                    else:  # router bgp X
                        device_bgp_cbd.redistribute.static.create()
                        if protocol['import-policy']:
                            device_bgp_cbd.redistribute.static.route_map = protocol['import-policy']
                elif protocol['src-protocol'] == 'oc-pol-types:DIRECTLY_CONNECTED' and protocol['address-family'] == 'oc-types:IPV4':
                    if service_protocol.bgp.oc_netinst__global.afi_safis.afi_safi:
                        if network_instance_type == 'oc-ni-types:DEFAULT_INSTANCE':  # address-family ipv4 unicast
                            device_bgp_cbd.address_family.ipv4['unicast'].redistribute.connected.create()
                            if protocol['import-policy']:
                                device_bgp_cbd.address_family.ipv4['unicast'].redistribute.connected.route_map = \
                                protocol['import-policy']
                        elif network_instance_type == 'oc-ni-types:L3VRF':  # address-family ipv4 unicast vrf
                            device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf[
                                vrf_name].redistribute.connected.create()
                            if protocol['import-policy']:
                                device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf[
                                    vrf_name].redistribute.connected.route_map = protocol['import-policy']
                    else:  # router bgp X
                        device_bgp_cbd.redistribute.connected.create()
                        if protocol['import-policy']:
                            device_bgp_cbd.redistribute.connected.route_map = protocol['import-policy']
                elif protocol['src-protocol'] == 'oc-pol-types:ISIS' and protocol['address-family'] == 'oc-types:IPV4':
                    pass


def apply_policy(neighbor_object_cdb, afi_safi_service) -> None:
    """
    Applies route-maps to neighbors and peer-groups
    """
    if afi_safi_service.apply_policy.config.export_policy:
        if len(afi_safi_service.apply_policy.config.export_policy) == 1:
            rm = neighbor_object_cdb.route_map.create('out')
            rm.route_map_name = afi_safi_service.apply_policy.config.export_policy.as_list()[0]
        else:
            raise ValueError('XE BGP neighbors and peer groups support one outbound policy')
    if afi_safi_service.apply_policy.config.import_policy:
        if len(afi_safi_service.apply_policy.config.import_policy) == 1:
            rm = neighbor_object_cdb.route_map.create('in')
            rm.route_map_name = afi_safi_service.apply_policy.config.import_policy.as_list()[0]
        else:
            raise ValueError('XE BGP neighbors and peer groups support one inbound policy')


def remove_private_as(neighbor_object_cdb, object_service) -> None:
    """
    Configure remote private-as options
    """
    neighbor_object_cdb.remove_private_as.create()
    if object_service.config.remove_private_as == 'oc-bgp-types:PRIVATE_AS_REMOVE_ALL':
        neighbor_object_cdb.remove_private_as.all.create()
    elif object_service.config.remove_private_as == 'oc-bgp-types:PRIVATE_AS_REPLACE_ALL':
        neighbor_object_cdb.remove_private_as.all.create()
        neighbor_object_cdb.remove_private_as.replace_as.create()


def send_community(neighbor_object_cdb, object_service) -> None:
    """
    Configure community options
    """
    neighbor_object_cdb.send_community.create()
    if object_service.config.send_community == 'STANDARD':
        neighbor_object_cdb.send_community.send_community_where = 'standard'
    elif object_service.config.send_community == 'EXTENDED':
        neighbor_object_cdb.send_community.send_community_where = 'extended'
    elif object_service.config.send_community == 'BOTH':
        neighbor_object_cdb.send_community.send_community_where = 'both'


def ebgp_multihop(neighbor_object_cdb, object_service) -> None:
    """
    Configure ebgp_multihop
    """
    if object_service.ebgp_multihop.config.enabled and object_service.ebgp_multihop.config.multihop_ttl:
        neighbor_object_cdb.ebgp_multihop.create()
        neighbor_object_cdb.ebgp_multihop.max_hop = object_service.ebgp_multihop.config.multihop_ttl


def route_reflector(neighbor_object_cdb, object_service) -> None:
    """
    Configure route_reflector
    """
    if object_service.route_reflector.config.route_reflector_client:
        neighbor_object_cdb.route_reflector_client.create()
    if object_service.route_reflector.config.route_reflector_cluster_id:
        neighbor_object_cdb.cluster_id = object_service.route_reflector.config.route_reflector_cluster_id


def timers(neighbor_object_cdb, object_service) -> None:
    """
    Configure timers
    """
    if object_service.timers.config.hold_time and object_service.timers.config.keepalive_interval:
        neighbor_object_cdb.timers.holdtime = int(float(object_service.timers.config.hold_time))
        neighbor_object_cdb.timers.keepalive_interval = int(
            float(object_service.timers.config.keepalive_interval))


def transport(neighbor_object_cdb, object_service) -> None:
    """
    Configure transport
    """
    if object_service.transport.config.mtu_discovery is False:
        neighbor_object_cdb.transport.path_mtu_discovery.create()
        neighbor_object_cdb.transport.path_mtu_discovery.disable.create()
    elif object_service.transport.config.mtu_discovery:
        neighbor_object_cdb.transport.path_mtu_discovery.create()
    if object_service.transport.config.passive_mode:
        neighbor_object_cdb.transport.connection_mode = 'passive'
    if object_service.transport.config.local_address:  # TODO add check and translation from IP
        interface_type, interface_number = xe_get_interface_type_and_number(
            object_service.transport.config.local_address)
        neighbor_object_cdb.update_source[interface_type] = interface_number


def xe_bgp_neighbors_program_service(self, service_protocol, network_instance_type, vrf_name) -> None:
    """
    Program service for xe NED features
    """
    # If not afi then do below, else create the neighbors in the appropriate afis
    self.log.info(f'{self.device_name} BGP neighbors')
    asn = service_protocol.bgp.oc_netinst__global.config.oc_netinst__as
    if asn:
        for service_bgp_neighbor in service_protocol.bgp.neighbors.neighbor:
            if service_bgp_neighbor.neighbor_address and (
                    service_bgp_neighbor.config.peer_as or service_bgp_neighbor.config.peer_group):
                if not self.root.devices.device[self.device_name].config.ios__router.bgp[asn].neighbor.exists(
                        service_bgp_neighbor.neighbor_address):
                    self.root.devices.device[self.device_name].config.ios__router.bgp[asn].neighbor.create(
                        service_bgp_neighbor.neighbor_address)
                neighbor = self.root.devices.device[self.device_name].config.ios__router.bgp[asn].neighbor[
                    service_bgp_neighbor.neighbor_address]

                xe_bgp_configure_neighbor(service_bgp_neighbor, neighbor)

                if service_bgp_neighbor.afi_safis.afi_safi:
                    device_bgp_cbd = self.root.devices.device[self.device_name].config.ios__router.bgp[asn]
                    for afi_safi_service in service_bgp_neighbor.afi_safis.afi_safi:
                        if network_instance_type == 'oc-ni-types:DEFAULT_INSTANCE' and afi_safi_service.config.enabled:
                            if afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV4_UNICAST':
                                if not device_bgp_cbd.address_family.ipv4['unicast'].neighbor.exists(
                                        service_bgp_neighbor.neighbor_address):
                                    device_bgp_cbd.address_family.ipv4['unicast'].neighbor.create(
                                        service_bgp_neighbor.neighbor_address)
                                neighbor_object_cdb = device_bgp_cbd.address_family.ipv4['unicast'].neighbor[
                                    service_bgp_neighbor.neighbor_address]
                                if not neighbor_object_cdb.activate.exists():
                                    neighbor_object_cdb.activate.create()
                                apply_policy(neighbor_object_cdb, afi_safi_service)
                                if service_bgp_neighbor.config.send_community and service_bgp_neighbor.config.send_community != 'NONE':
                                    send_community(neighbor_object_cdb, service_bgp_neighbor)
                            elif afi_safi_service.config.afi_safi_name == 'oc-bgp-types:L3VPN_IPV4_UNICAST':
                                if not device_bgp_cbd.address_family.vpnv4['unicast'].neighbor.exists(
                                        service_bgp_neighbor.neighbor_address):
                                    device_bgp_cbd.address_family.vpnv4['unicast'].neighbor.create(
                                        service_bgp_neighbor.neighbor_address)
                                neighbor_object_cdb = device_bgp_cbd.address_family.vpnv4['unicast'].neighbor[
                                    service_bgp_neighbor.neighbor_address]
                                if not neighbor_object_cdb.activate.exists():
                                    neighbor_object_cdb.activate.create()
                                apply_policy(neighbor_object_cdb, afi_safi_service)
                                if service_bgp_neighbor.config.send_community and service_bgp_neighbor.config.send_community != 'NONE':
                                    send_community(neighbor_object_cdb, service_bgp_neighbor)
                            elif afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV6_UNICAST':  # TODO
                                pass
                            elif afi_safi_service.config.afi_safi_name == 'oc-bgp-types:L3VPN_IPV6_UNICAST':  # TODO
                                pass
                        elif network_instance_type == 'oc-ni-types:L3VRF' and afi_safi_service.config.enabled:
                            if afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV4_UNICAST' or \
                                    afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV4_LABELED_UNICAST':
                                if not device_bgp_cbd.address_family.with_vrf.ipv4.exists('unicast'):
                                    device_bgp_cbd.address_family.with_vrf.ipv4.create('unicast')
                                if not device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf.exists(vrf_name):
                                    device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf.create(vrf_name)
                                family_ipv4_unicast_vrf = device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf[
                                    vrf_name]
                                if not family_ipv4_unicast_vrf.neighbor.exists(service_bgp_neighbor.neighbor_address):
                                    family_ipv4_unicast_vrf.neighbor.create(service_bgp_neighbor.neighbor_address)
                                neighbor_object_cdb = family_ipv4_unicast_vrf.neighbor[
                                    service_bgp_neighbor.neighbor_address]
                                xe_bgp_configure_neighbor(service_bgp_neighbor, neighbor_object_cdb)
                                if service_bgp_neighbor.config.send_community and service_bgp_neighbor.config.send_community != 'NONE':
                                    send_community(neighbor_object_cdb, service_bgp_neighbor)
                                if not neighbor_object_cdb.activate.exists():
                                    neighbor_object_cdb.activate.create()
                                apply_policy(neighbor_object_cdb, afi_safi_service)
                                if service_bgp_neighbor.as_path_options.config.replace_peer_as:
                                    neighbor_object_cdb.as_override.create()
                                if afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV4_LABELED_UNICAST':
                                    neighbor_object_cdb.send_label.create()
                else:  # standard BGP Neighbor community configuration
                    if service_bgp_neighbor.config.send_community and service_bgp_neighbor.config.send_community != 'NONE':
                        send_community(neighbor, service_bgp_neighbor)


def xe_bgp_configure_neighbor(service_bgp_neighbor, neighbor) -> None:
    if service_bgp_neighbor.apply_policy:
        if service_bgp_neighbor.apply_policy.config.export_policy:
            if len(service_bgp_neighbor.apply_policy.config.export_policy) == 1:
                rm = neighbor.route_map.create('out')
                rm.route_map_name = service_bgp_neighbor.apply_policy.config.export_policy.as_list()[0]
            else:
                raise ValueError('XE BGP neighbors support one outbound policy')
        if service_bgp_neighbor.apply_policy.config.import_policy:
            if len(service_bgp_neighbor.apply_policy.config.import_policy) == 1:
                rm = neighbor.route_map.create('in')
                rm.route_map_name = service_bgp_neighbor.apply_policy.config.import_policy.as_list()[0]
            else:
                raise ValueError('XE BGP neighbors support one inbound policy')
    if service_bgp_neighbor.config:
        if service_bgp_neighbor.config.peer_as:
            neighbor.remote_as = service_bgp_neighbor.config.peer_as
        if service_bgp_neighbor.config.auth_password:
            neighbor.password.text = service_bgp_neighbor.config.auth_password
        if service_bgp_neighbor.config.description:
            neighbor.description = service_bgp_neighbor.config.description
        if service_bgp_neighbor.config.enabled is False:
            neighbor.shutdown.create()
        elif service_bgp_neighbor.config.enabled and neighbor.shutdown.exists():
            neighbor.shutdown.delete()
        if service_bgp_neighbor.config.local_as:
            neighbor.local_as.create()
            neighbor.local_as.as_no = service_bgp_neighbor.config.local_as
        if service_bgp_neighbor.config.peer_group:
            neighbor.peer_group = service_bgp_neighbor.config.peer_group
        if service_bgp_neighbor.config.remove_private_as:
            remove_private_as(neighbor, service_bgp_neighbor)
    if service_bgp_neighbor.ebgp_multihop:
        ebgp_multihop(neighbor, service_bgp_neighbor)
    if service_bgp_neighbor.route_reflector:
        route_reflector(neighbor, service_bgp_neighbor)
    if service_bgp_neighbor.timers and not service_bgp_neighbor.config.peer_group:
        timers(neighbor, service_bgp_neighbor)
    if service_bgp_neighbor.transport:
        transport(neighbor, service_bgp_neighbor)


def xe_bgp_peer_groups_program_service(self, service_protocol, network_instance_type, vrf_name) -> None:
    """
    Program service for xe NED features
    """

    # helper functions
    def configure_global_peer_group() -> None:
        if service_bgp_peergroup.peer_group_name:
            if not self.root.devices.device[self.device_name].config.ios__router.bgp[asn].neighbor_tag.neighbor.exists(
                    service_bgp_peergroup.peer_group_name):
                self.root.devices.device[self.device_name].config.ios__router.bgp[asn].neighbor_tag.neighbor.create(
                    service_bgp_peergroup.peer_group_name)
            peer_group = \
                self.root.devices.device[self.device_name].config.ios__router.bgp[asn].neighbor_tag.neighbor[
                    service_bgp_peergroup.peer_group_name]
            if not peer_group.peer_group.exists():
                peer_group.peer_group.create()

            xe_bgp_configure_peer_group(service_bgp_peergroup, peer_group)

    # If not afi then do below, else create the peer-groups in the appropriate afis
    self.log.info(f'{self.device_name} BGP peer-groups')
    asn = service_protocol.bgp.oc_netinst__global.config.oc_netinst__as
    if asn:
        for service_bgp_peergroup in service_protocol.bgp.peer_groups.peer_group:
            flag_configure_global_peer_group = True
            if service_bgp_peergroup.afi_safis.afi_safi:
                device_bgp_cbd = self.root.devices.device[self.device_name].config.ios__router.bgp[asn]
                for afi_safi_service in service_bgp_peergroup.afi_safis.afi_safi:
                    if network_instance_type == 'oc-ni-types:DEFAULT_INSTANCE' and afi_safi_service.config.enabled:
                        if afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV4_UNICAST':
                            configure_global_peer_group()
                            if not device_bgp_cbd.address_family.ipv4['unicast'].neighbor_tag.neighbor.exists(
                                    service_bgp_peergroup.peer_group_name):
                                device_bgp_cbd.address_family.ipv4['unicast'].neighbor_tag.neighbor.create(
                                    service_bgp_peergroup.peer_group_name)
                            neighbor_object_cdb = device_bgp_cbd.address_family.ipv4['unicast'].neighbor_tag.neighbor[
                                service_bgp_peergroup.peer_group_name]
                            apply_policy(neighbor_object_cdb, afi_safi_service)
                            if service_bgp_peergroup.config.send_community and service_bgp_peergroup.config.send_community != 'NONE':
                                send_community(neighbor_object_cdb, service_bgp_peergroup)
                        elif afi_safi_service.config.afi_safi_name == 'oc-bgp-types:L3VPN_IPV4_UNICAST':
                            configure_global_peer_group()
                            if not device_bgp_cbd.address_family.vpnv4['unicast'].neighbor_tag.neighbor.exists(
                                    service_bgp_peergroup.peer_group_name):
                                device_bgp_cbd.address_family.vpnv4['unicast'].neighbor_tag.neighbor.create(
                                    service_bgp_peergroup.peer_group_name)
                            neighbor_object_cdb = device_bgp_cbd.address_family.vpnv4['unicast'].neighbor_tag.neighbor[
                                service_bgp_peergroup.peer_group_name]
                            apply_policy(neighbor_object_cdb, afi_safi_service)
                            if service_bgp_peergroup.config.send_community and service_bgp_peergroup.config.send_community != 'NONE':
                                send_community(neighbor_object_cdb, service_bgp_peergroup)
                        elif afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV6_UNICAST':  # TODO
                            pass
                        elif afi_safi_service.config.afi_safi_name == 'oc-bgp-types:L3VPN_IPV6_UNICAST':  # TODO
                            pass
                    elif network_instance_type == 'oc-ni-types:L3VRF' and afi_safi_service.config.enabled:
                        if afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV4_UNICAST' or \
                                afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV4_LABELED_UNICAST':
                            flag_configure_global_peer_group = False  # PEER GROUPS can not be used in multiple VRFs
                            if not device_bgp_cbd.address_family.with_vrf.ipv4.exists('unicast'):
                                device_bgp_cbd.address_family.with_vrf.ipv4.create('unicast')
                            if not device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf.exists(vrf_name):
                                device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf.create(vrf_name)
                            family_ipv4_unicast_vrf = device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf[
                                vrf_name]
                            if not family_ipv4_unicast_vrf.neighbor_tag.neighbor.exists(
                                    service_bgp_peergroup.peer_group_name):
                                family_ipv4_unicast_vrf.neighbor_tag.neighbor.create(
                                    service_bgp_peergroup.peer_group_name)
                            neighbor_object_cdb = family_ipv4_unicast_vrf.neighbor_tag.neighbor[
                                service_bgp_peergroup.peer_group_name]
                            if not neighbor_object_cdb.peer_group.exists():
                                neighbor_object_cdb.peer_group.create()
                            xe_bgp_configure_peer_group(service_bgp_peergroup, neighbor_object_cdb)
                            apply_policy(neighbor_object_cdb, afi_safi_service)
                            if service_bgp_peergroup.config.send_community and service_bgp_peergroup.config.send_community != 'NONE':
                                send_community(neighbor_object_cdb, service_bgp_peergroup)
                            if service_bgp_peergroup.as_path_options.config.replace_peer_as:
                                neighbor_object_cdb.as_override.create()
                            if afi_safi_service.config.afi_safi_name == 'oc-bgp-types:IPV4_LABELED_UNICAST':
                                neighbor_object_cdb.send_label.create()
            else:
                if service_bgp_peergroup.config.send_community and service_bgp_peergroup.config.send_community != 'NONE':
                    if service_bgp_peergroup.peer_group_name:
                        if not self.root.devices.device[self.device_name].config.ios__router.bgp[
                            asn].neighbor_tag.neighbor.exists(
                                service_bgp_peergroup.peer_group_name):
                            self.root.devices.device[self.device_name].config.ios__router.bgp[
                                asn].neighbor_tag.neighbor.create(
                                service_bgp_peergroup.peer_group_name)
                        peer_group = \
                            self.root.devices.device[self.device_name].config.ios__router.bgp[
                                asn].neighbor_tag.neighbor[
                                service_bgp_peergroup.peer_group_name]
                        if not peer_group.peer_group.exists():
                            peer_group.peer_group.create()
                        send_community(peer_group, service_bgp_peergroup)
            if flag_configure_global_peer_group:  # Flag will be False if peer group used in a VRF
                configure_global_peer_group()


def xe_bgp_configure_peer_group(service_bgp_peer_group, peer_group) -> None:
    if service_bgp_peer_group.apply_policy:
        if service_bgp_peer_group.apply_policy.config.export_policy:
            if len(service_bgp_peer_group.apply_policy.config.export_policy) == 1:
                rm = peer_group.route_map.create('out')
                rm.route_map_name = service_bgp_peer_group.apply_policy.config.export_policy.as_list()[0]
            else:
                raise ValueError('XE BGP peer groups support one outbound policy')
        if service_bgp_peer_group.apply_policy.config.import_policy:
            if len(service_bgp_peer_group.apply_policy.config.import_policy) == 1:
                rm = peer_group.route_map.create('in')
                rm.route_map_name = service_bgp_peer_group.apply_policy.config.import_policy.as_list()[0]
            else:
                raise ValueError('XE BGP peer groups support one inbound policy')
    if service_bgp_peer_group.config:
        if service_bgp_peer_group.config.peer_as:
            peer_group.remote_as = service_bgp_peer_group.config.peer_as
        if service_bgp_peer_group.config.auth_password:
            peer_group.password.text = service_bgp_peer_group.config.auth_password
        if service_bgp_peer_group.config.description:
            peer_group.description = service_bgp_peer_group.config.description
        if service_bgp_peer_group.config.local_as:
            peer_group.local_as.create()
            peer_group.local_as.as_no = service_bgp_peer_group.config.local_as
        if service_bgp_peer_group.config.remove_private_as:
            remove_private_as(peer_group, service_bgp_peer_group)
    if service_bgp_peer_group.ebgp_multihop:
        ebgp_multihop(peer_group, service_bgp_peer_group)
    if service_bgp_peer_group.route_reflector:
        route_reflector(peer_group, service_bgp_peer_group)
    if service_bgp_peer_group.timers:
        timers(peer_group, service_bgp_peer_group)
    if service_bgp_peer_group.transport:
        transport(peer_group, service_bgp_peer_group)
