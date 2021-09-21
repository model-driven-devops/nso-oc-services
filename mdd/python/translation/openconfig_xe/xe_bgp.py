# -*- mode: python; python-indent: 4 -*-


def xe_bgp_global_program_service(self) -> None:
    """
    Program service for xe NED features
    """
    if not self.root.devices.device[self.device_name].config.ios__router.bgp.exists(self.service.config.oc_bgp__as):
        self.root.devices.device[self.device_name].config.ios__router.bgp.create(self.service.config.oc_bgp__as)
    device_bgp_cbd = self.root.devices.device[self.device_name].config.ios__router.bgp[self.service.config.oc_bgp__as]
    if self.service.config.router_id:
        device_bgp_cbd.bgp.router_id = self.service.config.router_id
    if self.service.default_route_distance.config.external_route_distance and self.service.default_route_distance.config.internal_route_distance:  # because command needs ex, in, and local
        device_bgp_cbd.distance.bgp.extern_as = self.service.default_route_distance.config.external_route_distance
        device_bgp_cbd.distance.bgp.internal_as = self.service.default_route_distance.config.internal_route_distance
        device_bgp_cbd.distance.bgp.local = '200'  # TODO add this to extensions

    if self.service.graceful_restart:
        if self.service.graceful_restart.config.enabled:
            if not device_bgp_cbd.bgp.graceful_restart.exists():
                device_bgp_cbd.bgp.graceful_restart.create()
            if self.service.graceful_restart.config.restart_time:
                device_bgp_cbd.bgp.graceful_restart_conf.graceful_restart.restart_time = self.service.graceful_restart.config.restart_time
            if self.service.graceful_restart.config.stale_routes_time:
                device_bgp_cbd.bgp.graceful_restart_conf.graceful_restart.stalepath_time = int(
                    float(self.service.graceful_restart.config.stale_routes_time))

    if self.service.route_selection_options:
        if self.service.route_selection_options.config.always_compare_med:
            if not device_bgp_cbd.bgp.always_compare_med.exists():
                device_bgp_cbd.bgp.always_compare_med.create()
        if self.service.route_selection_options.config.external_compare_router_id:
            if not device_bgp_cbd.bgp.bestpath.compare_routerid.exists():
                device_bgp_cbd.bgp.bestpath.compare_routerid.create()

    if self.service.use_multiple_paths:
        if self.service.use_multiple_paths.config.enabled:
            if self.service.use_multiple_paths.ebgp.config.maximum_paths:
                device_bgp_cbd.maximum_paths.paths.number_of_paths = self.service.use_multiple_paths.ebgp.config.maximum_paths
            if self.service.use_multiple_paths.ebgp.config.allow_multiple_as:
                if not device_bgp_cbd.bgp.bestpath.as_path.multipath_relax.exists():
                    device_bgp_cbd.bgp.bestpath.as_path.multipath_relax.create()
            if self.service.use_multiple_paths.ibgp.config.maximum_paths:
                device_bgp_cbd.maximum_paths.ibgp.paths.number_of_paths = self.service.use_multiple_paths.ibgp.config.maximum_paths


def xe_bgp_neighbor_program_service(self) -> None:
    """
    Program service for xe NED features
    """
    asn = ''
    for i in self.root.devices.device[self.device_name].config.ios__router.bgp:
        asn = i.as_no
        break
    if asn:
        if self.service.neighbor_address and self.service.config.peer_as:
            if not self.root.devices.device[self.device_name].config.ios__router.bgp[asn].neighbor.exists(self.service.neighbor_address):
                self.root.devices.device[self.device_name].config.ios__router.bgp[asn].neighbor.create(self.service.neighbor_address)
            neighbor = self.root.devices.device[self.device_name].config.ios__router.bgp[asn].neighbor[self.service.neighbor_address]
            neighbor.remote_as = self.service.config.peer_as
            if self.service.config:
                if self.service.config.auth_password:
                    neighbor.password.text = self.service.config.auth_password
                if self.service.config.description:
                    neighbor.description = self.service.config.description
                if not self.service.config.enabled:
                    neighbor.shutdown.create()
                if self.service.config.local_as:
                    neighbor.local_as.create()
                    neighbor.local_as.as_no = self.service.config.local_as
                if self.service.config.remove_private_as:
                    neighbor.remove_private_as.create()
                    if self.service.config.remove_private_as == 'oc-bgp-types:PRIVATE_AS_REMOVE_ALL':
                        neighbor.remove_private_as.all.create()
                    elif self.service.config.remove_private_as == 'oc-bgp-types:PRIVATE_AS_REPLACE_ALL':
                        neighbor.remove_private_as.all.create()
                        neighbor.remove_private_as.replace_as.create()
                if self.service.config.send_community and self.service.config.send_community != 'NONE':
                    neighbor.send_community.create()
                    if self.service.config.send_community == 'STANDARD':
                        neighbor.send_community.send_community_where = 'standard'
                    elif self.service.config.send_community == 'EXTENDED':
                        neighbor.send_community.send_community_where = 'extended'
                    elif self.service.config.send_community == 'BOTH':
                        neighbor.send_community.send_community_where = 'both'
            if self.service.ebgp_multihop:
                if self.service.ebgp_multihop.config.enabled and self.service.ebgp_multihop.config.multihop_ttl:
                    neighbor.ebgp_multihop.create()
                    neighbor.ebgp_multihop.max_hop = self.service.ebgp_multihop.config.multihop_ttl
            if self.service.route_reflector:
                if self.service.route_reflector.config.route_reflector_client:
                    neighbor.route_reflector_client.create()
                if self.service.route_reflector.config.route_reflector_cluster_id:
                    neighbor.cluster_id = self.service.route_reflector.config.route_reflector_cluster_id
            if self.service.timers:
                if self.service.timers.config.hold_time and self.service.timers.config.keepalive_interval:
                    neighbor.timers.holdtime = int(float(self.service.timers.config.hold_time))
                    neighbor.timers.keepalive_interval = int(float(self.service.timers.config.keepalive_interval))
            if self.service.transport:
                if not self.service.transport.config.mtu_discovery:
                    neighbor.transport.path_mtu_discovery.create()
                    neighbor.transport.path_mtu_discovery.disable.create()
                if self.service.transport.config.passive_mode:
                    neighbor.transport.connection_mode = 'passive'


def xe_bgp_peergroup_program_service(self) -> None:
    """
    Program service for xe NED features
    """
    self.log.info(f'SELF SERVICE  {self.service}')
    self.log.info(f'DIR SELF SERVICE {dir(self.service)}')