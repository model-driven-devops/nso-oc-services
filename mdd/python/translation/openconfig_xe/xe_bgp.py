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
        for afi_safi in service_bgp_global.afi_safis.afi_safi:
            if network_instance_type == 'oc-ni-types:DEFAULT_INSTANCE' and afi_safi.config.enabled:
                if afi_safi.config.afi_safi_name == 'oc-bgp-types:IPV4_UNICAST':
                    if not device_bgp_cbd.address_family.ipv4.exists('unicast'):
                        device_bgp_cbd.address_family.ipv4.create('unicast')
                elif afi_safi.config.afi_safi_name == 'oc-bgp-types:L3VPN_IPV4_UNICAST':
                    if not device_bgp_cbd.address_family.vpnv4.exists('unicast'):
                        device_bgp_cbd.address_family.vpnv4.create('unicast')
                elif afi_safi.config.afi_safi_name == 'oc-bgp-types:IPV6_UNICAST':  # TODO
                    pass
                elif afi_safi.config.afi_safi_name == 'oc-bgp-types:L3VPN_IPV6_UNICAST':  # TODO
                    pass
            elif network_instance_type == 'oc-ni-types:L3VRF' and afi_safi.config.enabled:
                if afi_safi.config.afi_safi_name == 'oc-bgp-types:IPV4_UNICAST':
                    if not device_bgp_cbd.address_family.with_vrf.ipv4.exists('unicast'):
                        device_bgp_cbd.address_family.with_vrf.ipv4.create('unicast')
                    if not device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf.exists(vrf_name):
                        device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf.create(vrf_name)
                elif afi_safi.config.afi_safi_name == 'oc-bgp-types:IPV6_UNICAST':  # TODO
                    pass


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

                xe_bgp_configure_neighbor(self, service_bgp_neighbor, neighbor)

                if service_bgp_neighbor.afi_safis.afi_safi:
                    device_bgp_cbd = self.root.devices.device[self.device_name].config.ios__router.bgp[asn]
                    for afi_safi in service_bgp_neighbor.afi_safis.afi_safi:
                        if network_instance_type == 'oc-ni-types:DEFAULT_INSTANCE' and afi_safi.config.enabled:
                            if afi_safi.config.afi_safi_name == 'oc-bgp-types:IPV4_UNICAST':
                                if not device_bgp_cbd.address_family.ipv4['unicast'].neighbor.exists(service_bgp_neighbor.neighbor_address):
                                    device_bgp_cbd.address_family.ipv4['unicast'].neighbor.create(
                                        service_bgp_neighbor.neighbor_address)
                                family_neighbor_ipv4_unicast = device_bgp_cbd.address_family.ipv4['unicast'].neighbor[service_bgp_neighbor.neighbor_address]
                                if not family_neighbor_ipv4_unicast.activate.exists():
                                    family_neighbor_ipv4_unicast.activate.create()
# TODO add policies
                            elif afi_safi.config.afi_safi_name == 'oc-bgp-types:L3VPN_IPV4_UNICAST':
                                if not device_bgp_cbd.address_family.vpnv4['unicast'].neighbor.exists(
                                        service_bgp_neighbor.neighbor_address):
                                    device_bgp_cbd.address_family.vpnv4['unicast'].neighbor.create(
                                        service_bgp_neighbor.neighbor_address)
                                family_neighbor_vpnv4_unicast = device_bgp_cbd.address_family.vpnv4['unicast'].neighbor[
                                    service_bgp_neighbor.neighbor_address]
                                if not family_neighbor_vpnv4_unicast.activate.exists():
                                    family_neighbor_vpnv4_unicast.activate.create()
# TODO add policies
                            elif afi_safi.config.afi_safi_name == 'oc-bgp-types:IPV6_UNICAST':  # TODO
                                pass
                            elif afi_safi.config.afi_safi_name == 'oc-bgp-types:L3VPN_IPV6_UNICAST':  # TODO
                                pass
                        elif network_instance_type == 'oc-ni-types:L3VRF' and afi_safi.config.enabled:  # TODO VRF peers
                            self.log.info(f"Under elif network_instance_type == 'oc-ni-types:L3VRF' and afi_safi.config.enabled: network_instance_type {network_instance_type}")
                            if afi_safi.config.afi_safi_name == 'oc-bgp-types:IPV4_UNICAST':
                                if not device_bgp_cbd.address_family.with_vrf.ipv4.exists('unicast'):
                                    device_bgp_cbd.address_family.with_vrf.ipv4.create('unicast')
                                if not device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf.exists(vrf_name):
                                    device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf.create(vrf_name)
                                family_ipv4_unicast_vrf = device_bgp_cbd.address_family.with_vrf.ipv4['unicast'].vrf[vrf_name]
                                self.log.info(f'service_bgp_neighbor.neighbor_address  {service_bgp_neighbor.neighbor_address}')
                                if not family_ipv4_unicast_vrf.neighbor.exists(service_bgp_neighbor.neighbor_address):
                                    family_ipv4_unicast_vrf.neighbor.create(service_bgp_neighbor.neighbor_address)
                                neighbor = family_ipv4_unicast_vrf.neighbor[service_bgp_neighbor.neighbor_address]
                                xe_bgp_configure_neighbor(self, service_bgp_neighbor, neighbor)
                                # neighbor.remote_as = service_bgp_neighbor.config.peer_as
                                if not neighbor.activate.exists():
                                    neighbor.activate.create()


def xe_bgp_configure_neighbor(self, service_bgp_neighbor, neighbor) -> None:
    self.log.info(f'def xe_bgp_configure_neighbor service_bgp_neighbor.config.peer_as  {service_bgp_neighbor.config.peer_as}')
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
            neighbor.remove_private_as.create()
            if service_bgp_neighbor.config.remove_private_as == 'oc-bgp-types:PRIVATE_AS_REMOVE_ALL':
                neighbor.remove_private_as.all.create()
            elif service_bgp_neighbor.config.remove_private_as == 'oc-bgp-types:PRIVATE_AS_REPLACE_ALL':
                neighbor.remove_private_as.all.create()
                neighbor.remove_private_as.replace_as.create()
        if service_bgp_neighbor.config.send_community and service_bgp_neighbor.config.send_community != 'NONE':
            neighbor.send_community.create()
            if service_bgp_neighbor.config.send_community == 'STANDARD':
                neighbor.send_community.send_community_where = 'standard'
            elif service_bgp_neighbor.config.send_community == 'EXTENDED':
                neighbor.send_community.send_community_where = 'extended'
            elif service_bgp_neighbor.config.send_community == 'BOTH':
                neighbor.send_community.send_community_where = 'both'

    if service_bgp_neighbor.ebgp_multihop:
        if service_bgp_neighbor.ebgp_multihop.config.enabled and service_bgp_neighbor.ebgp_multihop.config.multihop_ttl:
            neighbor.ebgp_multihop.create()
            neighbor.ebgp_multihop.max_hop = service_bgp_neighbor.ebgp_multihop.config.multihop_ttl
    if service_bgp_neighbor.route_reflector:
        if service_bgp_neighbor.route_reflector.config.route_reflector_client:
            neighbor.route_reflector_client.create()
        if service_bgp_neighbor.route_reflector.config.route_reflector_cluster_id:
            neighbor.cluster_id = service_bgp_neighbor.route_reflector.config.route_reflector_cluster_id
    if service_bgp_neighbor.timers and not service_bgp_neighbor.config.peer_group:
        if service_bgp_neighbor.timers.config.hold_time and service_bgp_neighbor.timers.config.keepalive_interval:
            neighbor.timers.holdtime = int(float(service_bgp_neighbor.timers.config.hold_time))
            neighbor.timers.keepalive_interval = int(
                float(service_bgp_neighbor.timers.config.keepalive_interval))
    if service_bgp_neighbor.transport:
        if service_bgp_neighbor.transport.config.mtu_discovery is False:
            neighbor.transport.path_mtu_discovery.create()
            neighbor.transport.path_mtu_discovery.disable.create()
        elif service_bgp_neighbor.transport.config.mtu_discovery:
            neighbor.transport.path_mtu_discovery.create()
        if service_bgp_neighbor.transport.config.passive_mode:
            neighbor.transport.connection_mode = 'passive'
        if service_bgp_neighbor.transport.config.local_address:  # TODO add check and translation from IP
            interface_type, interface_number = xe_get_interface_type_and_number(
                service_bgp_neighbor.transport.config.local_address)
            neighbor.update_source[interface_type] = interface_number


def xe_bgp_peergroups_program_service(self, service_protocol, network_instance_type, vrf_name) -> None:
    """
    Program service for xe NED features
    """
    self.log.info(f'{self.device_name} BGP peer groups')
    asn = service_protocol.bgp.oc_netinst__global.config.oc_netinst__as
    if asn:
        for service_bgp_peergroup in service_protocol.bgp.peer_groups.peer_group:
            if service_bgp_peergroup.peer_group_name:
                if not self.root.devices.device[self.device_name].config.ios__router.bgp[
                    asn].neighbor_tag.neighbor.exists(
                        service_bgp_peergroup.peer_group_name):
                    self.root.devices.device[self.device_name].config.ios__router.bgp[asn].neighbor_tag.neighbor.create(
                        service_bgp_peergroup.peer_group_name)

                peer_group = \
                self.root.devices.device[self.device_name].config.ios__router.bgp[asn].neighbor_tag.neighbor[
                    service_bgp_peergroup.peer_group_name]
                if not peer_group.peer_group.exists():
                    peer_group.peer_group.create()

                if service_bgp_peergroup.config:
                    if service_bgp_peergroup.config.peer_as:
                        peer_group.remote_as = service_bgp_peergroup.config.peer_as
                    if service_bgp_peergroup.config.auth_password:
                        peer_group.password.text = service_bgp_peergroup.config.auth_password
                    if service_bgp_peergroup.config.description:
                        peer_group.description = service_bgp_peergroup.config.description
                    if service_bgp_peergroup.config.local_as:
                        peer_group.local_as.create()
                        peer_group.local_as.as_no = service_bgp_peergroup.config.local_as
                    if service_bgp_peergroup.config.remove_private_as:
                        peer_group.remove_private_as.create()
                        if service_bgp_peergroup.config.remove_private_as == 'oc-bgp-types:PRIVATE_AS_REMOVE_ALL':
                            peer_group.remove_private_as.all.create()
                        elif service_bgp_peergroup.config.remove_private_as == 'oc-bgp-types:PRIVATE_AS_REPLACE_ALL':
                            peer_group.remove_private_as.all.create()
                            peer_group.remove_private_as.replace_as.create()
                    if service_bgp_peergroup.config.send_community and service_bgp_peergroup.config.send_community != 'NONE':
                        peer_group.send_community.create()
                        if service_bgp_peergroup.config.send_community == 'STANDARD':
                            peer_group.send_community.send_community_where = 'standard'
                        elif service_bgp_peergroup.config.send_community == 'EXTENDED':
                            peer_group.send_community.send_community_where = 'extended'
                        elif service_bgp_peergroup.config.send_community == 'BOTH':
                            peer_group.send_community.send_community_where = 'both'
                if service_bgp_peergroup.ebgp_multihop:
                    if service_bgp_peergroup.ebgp_multihop.config.enabled and service_bgp_peergroup.ebgp_multihop.config.multihop_ttl:
                        peer_group.ebgp_multihop.create()
                        peer_group.ebgp_multihop.max_hop = service_bgp_peergroup.ebgp_multihop.config.multihop_ttl
                if service_bgp_peergroup.route_reflector:
                    if service_bgp_peergroup.route_reflector.config.route_reflector_client:
                        peer_group.route_reflector_client.create()
                    if service_bgp_peergroup.route_reflector.config.route_reflector_cluster_id:
                        peer_group.cluster_id = service_bgp_peergroup.route_reflector.config.route_reflector_cluster_id
                if service_bgp_peergroup.timers:
                    if service_bgp_peergroup.timers.config.hold_time and service_bgp_peergroup.timers.config.keepalive_interval:
                        peer_group.timers.holdtime = int(float(service_bgp_peergroup.timers.config.hold_time))
                        peer_group.timers.keepalive_interval = int(
                            float(service_bgp_peergroup.timers.config.keepalive_interval))
                if service_bgp_peergroup.transport:
                    if service_bgp_peergroup.transport.config.mtu_discovery is False:
                        peer_group.transport.path_mtu_discovery.create()
                        peer_group.transport.path_mtu_discovery.disable.create()
                    elif service_bgp_peergroup.transport.config.mtu_discovery:
                        peer_group.transport.path_mtu_discovery.create()
                    if service_bgp_peergroup.transport.config.passive_mode:
                        peer_group.transport.connection_mode = 'passive'
                    if service_bgp_peergroup.transport.config.local_address:  # TODO add check and translation from IP
                        interface_type, interface_number = xe_get_interface_type_and_number(
                            service_bgp_peergroup.transport.config.local_address)
                        peer_group.update_source[interface_type] = interface_number
