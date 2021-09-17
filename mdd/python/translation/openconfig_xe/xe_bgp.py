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
        self.log.info(f'Vlaue {self.service.graceful_restart.config.restart_time}')
        self.log.info(f'Type {type(self.service.graceful_restart.config.restart_time)}')
        self.log.info(f'Vlaue {self.service.graceful_restart.config.stale_routes_time}')
        self.log.info(f'Type {type(self.service.graceful_restart.config.stale_routes_time)}')
        self.log.info(f'Vlaue {self.service.graceful_restart.config.enabled}')
        self.log.info(f'Type {type(self.service.graceful_restart.config.enabled)}')
        if self.service.graceful_restart.config.enabled:
            if not device_bgp_cbd.bgp.graceful_restart.exists():
                device_bgp_cbd.bgp.graceful_restart.create()
            if self.service.graceful_restart.config.restart_time:
                device_bgp_cbd.bgp.graceful_restart_conf.graceful_restart.restart_time = self.service.graceful_restart.config.restart_time
            if self.service.graceful_restart.config.stale_routes_time:
                device_bgp_cbd.bgp.graceful_restart_conf.graceful_restart.stalepath_time = int(float(self.service.graceful_restart.config.stale_routes_time))

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
    self.log.info(f'SELF SERVICE  {self.service}')
    self.log.info(f'DIR SELF SERVICE {dir(self.service)}')


def xe_bgp_peergroup_program_service(self) -> None:
    """
    Program service for xe NED features
    """
    self.log.info(f'SELF SERVICE  {self.service}')
    self.log.info(f'DIR SELF SERVICE {dir(self.service)}')
