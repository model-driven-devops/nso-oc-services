# -*- mode: python; python-indent: 4 -*-
from translation.common import get_interface_type_number_and_subinterface

ospf_network_types = {
    'oc-ospf-types:BROADCAST_NETWORK': 'broadcast',
    'oc-ospf-types:POINT_TO_POINT_NETWORK': 'point-to-point',
    'oc-ospf-types:NON_BROADCAST_NETWORK': 'non-broadcast'
}


def xe_ospf_program_service(self, service_protocol, network_instance_type, vrf_name) -> None:
    """
    Program service for xe NED features
    """
    self.log.info(f'{self.device_name} OSPF')
    # Process
    if not self.root.devices.device[self.device_name].config.ios__router.ospf.exists(service_protocol.name):
        self.root.devices.device[self.device_name].config.ios__router.ospf.create(service_protocol.name)
    device_ospf_cbd = self.root.devices.device[self.device_name].config.ios__router.ospf[
        service_protocol.name]
    # Process VRF
    if network_instance_type == 'oc-ni-types:L3VRF':
        device_ospf_cbd.vrf = vrf_name
    # Router-ID
    if service_protocol.ospfv2.oc_netinst__global.config.router_id:
        device_ospf_cbd.router_id = service_protocol.ospfv2.oc_netinst__global.config.router_id
    # log_adjacency_changes
    if service_protocol.ospfv2.oc_netinst__global.config.log_adjacency_changes:
        device_ospf_cbd.log_adjacency_changes.create()
    # prefix_suppression
    if service_protocol.ospfv2.oc_netinst__global.config.hide_transit_only_networks:
        device_ospf_cbd.prefix_suppression.create()
    # summary-route-cost-mode
    if service_protocol.ospfv2.oc_netinst__global.config.summary_route_cost_mode == 'RFC2328_COMPATIBLE':
        device_ospf_cbd.compatible.rfc1583 = False
    elif service_protocol.ospfv2.oc_netinst__global.config.summary_route_cost_mode == 'RFC1583_COMPATIBLE':
        device_ospf_cbd.compatible.rfc1583 = True
    # Graceful Restart IETF
    if service_protocol.ospfv2.oc_netinst__global.graceful_restart.config.enabled:
        device_ospf_cbd.nsf_ietf.nsf.ietf.create()
    elif service_protocol.ospfv2.oc_netinst__global.graceful_restart.config.enabled is False:
        if device_ospf_cbd.nsf_ietf.nsf.ietf.exists():
            device_ospf_cbd.nsf_ietf.nsf.ietf.delete()
    # Capability VRF Lite
    if service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__capability_vrf_lite:
        device_ospf_cbd.capability.vrf_lite.create()
    elif service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__capability_vrf_lite is False:
        if device_ospf_cbd.capability.vrf_lite.exists():
            device_ospf_cbd.capability.vrf_lite.delete()
    # Default-Information Originate
    if service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__default_information_originate.config.enabled:
        device_ospf_cbd.default_information.originate.create()
        if service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__default_information_originate.config.always:
            device_ospf_cbd.default_information.originate.always.create()
        elif service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__default_information_originate.config.always is False:
            if device_ospf_cbd.default_information.originate.always.exists():
                device_ospf_cbd.default_information.originate.always.delete()
        if service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__default_information_originate.config.metric:
            device_ospf_cbd.default_information.originate.metric = service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__default_information_originate.config.metric
        if service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__default_information_originate.config.metric_type:
            device_ospf_cbd.default_information.originate.metric_type = service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__default_information_originate.config.metric_type
        if service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__default_information_originate.config.route_map:
            device_ospf_cbd.default_information.originate.route_map = service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__default_information_originate.config.route_map
    elif service_protocol.ospfv2.oc_netinst__global.config.oc_ospfv2_ext__default_information_originate.config.enabled is False:
        if device_ospf_cbd.default_information.originate.exists():
            device_ospf_cbd.default_information.originate.delete()
    # Inter-area propagation policy
    if len(service_protocol.ospfv2.oc_netinst__global.inter_area_propagation_policies.inter_area_propagation_policy) > 0:
        for service_policy in service_protocol.ospfv2.oc_netinst__global.inter_area_propagation_policies.inter_area_propagation_policy:
            if len(service_policy.config.import_policy.as_list()) == 1:
                if not device_ospf_cbd.area.exists(service_policy.dst_area):
                    device_ospf_cbd.area.create(service_policy.dst_area)
                area = device_ospf_cbd.area[service_policy.dst_area]
                if not area.filter_list.exists('in'):
                    area.filter_list.create('in')
                filter_list = area.filter_list['in']
                filter_list.prefix = service_policy.config.import_policy.as_list()[0]
            else:
                raise ValueError('XE OSPF inter-area filter-list in supports one list')
    # mpls_ldp_igp_sync
    if service_protocol.ospfv2.oc_netinst__global.mpls.igp_ldp_sync.config.enabled:
        device_ospf_cbd.mpls.ldp.sync.create()
    elif service_protocol.ospfv2.oc_netinst__global.mpls.igp_ldp_sync.config.enabled is False:
        if device_ospf_cbd.mpls.ldp.sync.exists():
            device_ospf_cbd.mpls.ldp.sync.delete()
    # timers_lsa
    if service_protocol.ospfv2.oc_netinst__global.timers.lsa_generation.config.initial_delay or \
            service_protocol.ospfv2.oc_netinst__global.timers.lsa_generation.config.maximum_delay or \
            service_protocol.ospfv2.oc_netinst__global.timers.lsa_generation.config.oc_ospfv2_ext__hold_time:
        if service_protocol.ospfv2.oc_netinst__global.timers.lsa_generation.config.initial_delay and \
                service_protocol.ospfv2.oc_netinst__global.timers.lsa_generation.config.maximum_delay and \
                service_protocol.ospfv2.oc_netinst__global.timers.lsa_generation.config.oc_ospfv2_ext__hold_time:
            device_ospf_cbd.timers.throttle.lsa.all.create()
            device_ospf_cbd.timers.throttle.lsa.start_interval = service_protocol.ospfv2.oc_netinst__global.timers.lsa_generation.config.initial_delay
            device_ospf_cbd.timers.throttle.lsa.hold_interval = service_protocol.ospfv2.oc_netinst__global.timers.lsa_generation.config.oc_ospfv2_ext__hold_time
            device_ospf_cbd.timers.throttle.lsa.max_interval = service_protocol.ospfv2.oc_netinst__global.timers.lsa_generation.config.maximum_delay
        else:
            raise ValueError(
                'XE OSPF throttle timers lsa needs values for start-interval, hold-interval, and max-interval')
    # timers_spf
    if service_protocol.ospfv2.oc_netinst__global.timers.spf.config.initial_delay or \
            service_protocol.ospfv2.oc_netinst__global.timers.spf.config.maximum_delay or \
            service_protocol.ospfv2.oc_netinst__global.timers.spf.config.oc_ospfv2_ext__hold_time:
        if service_protocol.ospfv2.oc_netinst__global.timers.spf.config.initial_delay and \
                service_protocol.ospfv2.oc_netinst__global.timers.spf.config.maximum_delay and \
                service_protocol.ospfv2.oc_netinst__global.timers.spf.config.oc_ospfv2_ext__hold_time:
            device_ospf_cbd.timers.throttle.spf.spf_start = service_protocol.ospfv2.oc_netinst__global.timers.spf.config.initial_delay
            device_ospf_cbd.timers.throttle.spf.spf_hold = service_protocol.ospfv2.oc_netinst__global.timers.spf.config.oc_ospfv2_ext__hold_time
            device_ospf_cbd.timers.throttle.spf.spf_max_wait = service_protocol.ospfv2.oc_netinst__global.timers.spf.config.maximum_delay
        else:
            raise ValueError('XE OSPF throttle timers spf needs values for spf-start, spf-hold, and spf-max-wait')
    # area
    if len(service_protocol.ospfv2.areas.area) > 0:
        for service_area in service_protocol.ospfv2.areas.area:
            if len(service_area.interfaces.interface) > 0:
                for service_interface in service_area.interfaces.interface:

                    interface_type, interface_number = get_interface_type_number_and_subinterface(
                        service_interface.id)
                    class_attribute = getattr(self.root.devices.device[self.device_name].config.ios__interface,
                                              interface_type)
                    interface_cdb = class_attribute[interface_number]
                    # router ospf network statement
                    create_area_network_statement(self, service_interface, device_ospf_cbd, service_area)
                    # interface ospf network type
                    if service_interface.config.network_type:
                        interface_cdb.ip.ospf.network = [ospf_network_types[service_interface.config.network_type]]
                    # interface ospf cost
                    if service_interface.config.metric:
                        interface_cdb.ip.ospf.cost = service_interface.config.metric
                    # interface passive
                    if service_interface.config.passive:
                        device_ospf_cbd.passive_interface.interface.create(service_interface.id)
                    elif service_interface.config.passive is False:
                        if device_ospf_cbd.passive_interface.interface.exists(service_interface.id):
                            device_ospf_cbd.passive_interface.interface.delete(service_interface.id)
                    # interface ospf priority
                    if service_interface.config.priority:
                        interface_cdb.ip.ospf.priority = service_interface.config.priority
                    # interface bfd
                    if service_interface.enable_bfd.config.enabled:
                        interface_cdb.ip.ospf.bfd.create()
                    elif service_interface.enable_bfd.config.enabled is False:
                        if interface_cdb.ip.ospf.bfd.exists():
                            interface_cdb.ip.ospf.bfd.delete()
                    # neighbors
                    if len(service_interface.neighbors.neighbor) > 0:
                        for service_neighbor in service_interface.neighbors.neighbor:
                            device_ospf_cbd.neighbor.create(service_neighbor.router_id)
                            if service_neighbor.config.metric:
                                device_ospf_cbd.neighbor[
                                    service_neighbor.router_id].cost_database_filter_container.cost = service_neighbor.config.metric
                    # timer hello-interval
                    if service_interface.timers.config.hello_interval:
                        interface_cdb.ip.ospf.hello_interval = service_interface.timers.config.hello_interval
                    # timer retransmission-interval
                    if service_interface.timers.config.retransmission_interval:
                        interface_cdb.ip.ospf.retransmit_interval = service_interface.timers.config.retransmission_interval
                    # timer dead-interval
                    if service_interface.timers.config.dead_interval:
                        interface_cdb.ip.ospf.dead_interval.seconds = service_interface.timers.config.dead_interval
                    # authentication
                    if service_interface.oc_ospfv2_ext__authentication.config.authentication_type == "UNCONFIGURED":
                        if interface_cdb.ip.ospf.authentication.exists():
                            del interface_cdb.ip.ospf.authentication
                    elif service_interface.oc_ospfv2_ext__authentication.config.authentication_type == "NULL":
                        if interface_cdb.ip.ospf.authentication.exists():
                            del interface_cdb.ip.ospf.authentication
                        interface_cdb.ip.ospf.authentication.create()
                        interface_cdb.ip.ospf.authentication.null.create()
                    elif service_interface.oc_ospfv2_ext__authentication.config.authentication_type == "MD5":
                        if len(service_interface.oc_ospfv2_ext__authentication.md5_authentication_keys.md5_authentication_key) > 0:
                            if interface_cdb.ip.ospf.authentication.exists():
                                del interface_cdb.ip.ospf.authentication
                            interface_cdb.ip.ospf.authentication.create()
                            interface_cdb.ip.ospf.authentication.message_digest.create()
                            for authentication_key in service_interface.oc_ospfv2_ext__authentication.md5_authentication_keys.md5_authentication_key:
                                interface_cdb.ip.ospf.message_digest_key.create(authentication_key.config.key_id)
                                interface_cdb.ip.ospf.message_digest_key[
                                    authentication_key.config.key_id].md5.secret = authentication_key.config.key
                        else:
                            raise ValueError("OSPF MD5 authentication must have at least one key configured.")
                    elif service_interface.oc_ospfv2_ext__authentication.config.authentication_type == "SIMPLE":
                        if interface_cdb.ip.ospf.authentication.exists():
                            del interface_cdb.ip.ospf.authentication
                        interface_cdb.ip.ospf.authentication.create()
                        if service_interface.oc_ospfv2_ext__authentication.config.simple_password:
                            interface_cdb.ip.ospf.authentication_key.secret = service_interface.oc_ospfv2_ext__authentication.config.simple_password
                            interface_cdb.ip.ospf.authentication_key.type = 0
            # mpls_traffic_eng_area
            if service_area.mpls.config.traffic_engineering_enabled:
                device_ospf_cbd.mpls.traffic_eng.area.create(service_area.identifier)
            elif service_area.mpls.config.traffic_engineering_enabled is False:
                if service_area.identifier in device_ospf_cbd.mpls.traffic_eng.area.as_list():
                    device_ospf_cbd.mpls.traffic_eng.area.remove(service_area.identifier)
            # virtual_link
            if len(service_area.virtual_links.virtual_link) > 0:
                if not device_ospf_cbd.area.exists(service_area.identifier):
                    device_ospf_cbd.area.create(service_area.identifier)
                for v_link in service_area.virtual_links.virtual_link:
                    device_ospf_cbd.area[service_area.identifier].virtual_link.create(v_link.remote_router_id)
            # stub areas - stub
            stub_counter = 0
            if service_area.oc_ospfv2_ext__stub_options.stub.config.enabled and service_area.oc_ospfv2_ext__stub_options.stub.config.default_information_originate:
                if not device_ospf_cbd.area.exists(service_area.identifier):
                    device_ospf_cbd.area.create(service_area.identifier)
                stub_counter += 1
                device_ospf_cbd.area[service_area.identifier].stub.create()
            elif service_area.oc_ospfv2_ext__stub_options.stub.config.enabled is False:
                if device_ospf_cbd.area.exists(service_area.identifier):
                    if device_ospf_cbd.area[service_area.identifier].stub.exists():
                        if service_area.oc_ospfv2_ext__stub_options.totally_stubby.config.enabled is False and service_area.oc_ospfv2_ext__stub_options.nssa.config.enabled is False:
                            device_ospf_cbd.area[service_area.identifier].stub.delete()
                            # TODO Must check for dependent area features before removing area
                            if len(service_protocol.ospfv2.oc_netinst__global.inter_area_propagation_policies.inter_area_propagation_policy) == 0:
                                del device_ospf_cbd.area[service_area.identifier]
            elif service_area.oc_ospfv2_ext__stub_options.stub.config.enabled and service_area.oc_ospfv2_ext__stub_options.stub.config.default_information_originate is False:
                raise ValueError('XE stub area ABRs must be configured to default_information_originate.')
            # stub areas - totally-stubby
            if service_area.oc_ospfv2_ext__stub_options.totally_stubby.config.enabled:
                if not device_ospf_cbd.area.exists(service_area.identifier):
                    device_ospf_cbd.area.create(service_area.identifier)
                stub_counter += 1
                device_ospf_cbd.area[service_area.identifier].stub.create()
                device_ospf_cbd.area[service_area.identifier].stub.no_summary.create()
            elif service_area.oc_ospfv2_ext__stub_options.totally_stubby.config.enabled is False:
                if device_ospf_cbd.area.exists(service_area.identifier):
                    if device_ospf_cbd.area[service_area.identifier].stub.exists():
                        if device_ospf_cbd.area[service_area.identifier].stub.no_summary.exists():
                            device_ospf_cbd.area[service_area.identifier].stub.no_summary.delete()
                        if service_area.oc_ospfv2_ext__stub_options.stub.config.enabled is False and service_area.oc_ospfv2_ext__stub_options.nssa.config.enabled is False:
                            device_ospf_cbd.area[service_area.identifier].stub.delete()
                            # TODO Must check for dependent area features before removing area
                            if len(service_protocol.ospfv2.oc_netinst__global.inter_area_propagation_policies.inter_area_propagation_policy) == 0:
                                del device_ospf_cbd.area[service_area.identifier]
            elif service_area.oc_ospfv2_ext__stub_options.totally_stubby.config.enabled and service_area.oc_ospfv2_ext__stub_options.totally_stubby.config.default_information_originate is False:
                raise ValueError('XE totally stubby area ABRs must be configured to default_information_originate.')
            # stub areas - nssa
            if service_area.oc_ospfv2_ext__stub_options.nssa.config.enabled:
                if not device_ospf_cbd.area.exists(service_area.identifier):
                    device_ospf_cbd.area.create(service_area.identifier)
                stub_counter += 1
                device_ospf_cbd.area[service_area.identifier].nssa.create()
                if service_area.oc_ospfv2_ext__stub_options.nssa.config.default_information_originate:
                    device_ospf_cbd.area[service_area.identifier].nssa.default_information_originate.create()
                elif service_area.oc_ospfv2_ext__stub_options.nssa.config.default_information_originate is False:
                    if device_ospf_cbd.area[service_area.identifier].nssa.default_information_originate.exists():
                        device_ospf_cbd.area[service_area.identifier].nssa.default_information_originate.delete()
                if service_area.oc_ospfv2_ext__stub_options.nssa.config.no_summary:
                    device_ospf_cbd.area[service_area.identifier].nssa.no_summary.create()
                elif service_area.oc_ospfv2_ext__stub_options.nssa.config.no_summary is False:
                    if device_ospf_cbd.area[service_area.identifier].nssa.no_summary.exists():
                        device_ospf_cbd.area[service_area.identifier].nssa.no_summary.delete()
            elif service_area.oc_ospfv2_ext__stub_options.nssa.config.enabled is False:
                if device_ospf_cbd.area.exists(service_area.identifier):
                    if device_ospf_cbd.area[service_area.identifier].nssa.exists():
                        device_ospf_cbd.area[service_area.identifier].nssa.delete()
                        if service_area.oc_ospfv2_ext__stub_options.stub.config.enabled is False and service_area.oc_ospfv2_ext__stub_options.totally_stubby.config.enabled is False:
                            # TODO Must check for dependent area features before removing area
                            if len(service_protocol.ospfv2.oc_netinst__global.inter_area_propagation_policies.inter_area_propagation_policy) == 0:
                                del device_ospf_cbd.area[service_area.identifier]
            if stub_counter > 1:
                raise ValueError(
                    'OSPF stub areas can only be type stub, totally-stubby, or nssa: not more than one type.')
    # Auto-cost reference-bandwidth
    if service_protocol.ospfv2.oc_netinst__global.config.auto_cost_ref_bandwidth:
        device_ospf_cbd.auto_cost.reference_bandwidth = service_protocol.ospfv2.oc_netinst__global.config.auto_cost_ref_bandwidth



def create_area_network_statement(self, service_interface, device_ospf_cbd, service_area) -> None:
    """
    If needed, creates ospf area and network statement for interface
    """
    if '.' in service_interface.id:
        int_name_and_subint = service_interface.id.split('.')
        interface_ip = str(self.root.devices.device[self.device_name].mdd__openconfig.oc_if__interfaces.interface[
                               int_name_and_subint[0]].subinterfaces.subinterface[
                               int_name_and_subint[1]].oc_ip__ipv4.addresses.address.keys()[0]).lstrip('{').rstrip('}')
    # what about tunnel, vlan, port-channel
    elif "Tunnel" in service_interface.id:
        interface_ip = str(self.root.devices.device[self.device_name].mdd__openconfig.oc_if__interfaces.interface[
                               service_interface.id].oc_tun__tunnel.ipv4.addresses.address.keys()[
                               0]).lstrip('{').rstrip('}')
    elif "Vlan" in service_interface.id:
        interface_ip = str(self.root.devices.device[self.device_name].mdd__openconfig.oc_if__interfaces.interface[
                               service_interface.id].oc_vlan__routed_vlan.oc_ip__ipv4.addresses.address.keys()[
                               0]).lstrip('{').rstrip('}')
    elif "Port-channel" in service_interface.id:
        interface_ip = str(self.root.devices.device[self.device_name].mdd__openconfig.oc_if__interfaces.interface[
                               service_interface.id].oc_lag__aggregation.oc_ip__ipv4.addresses.address.keys()[
                               0]).lstrip('{').rstrip('}')
    else:
        interface_ip = str(self.root.devices.device[self.device_name].mdd__openconfig.oc_if__interfaces.interface[
                               service_interface.id].subinterfaces.subinterface[0].oc_ip__ipv4.addresses.address.keys()[
                               0]).lstrip('{').rstrip('}')
    if not device_ospf_cbd.network.exists((interface_ip, '0.0.0.0')):
        device_ospf_cbd.network.create(interface_ip, '0.0.0.0')
    if device_ospf_cbd.network[(interface_ip, '0.0.0.0')].area != service_area.identifier:
        device_ospf_cbd.network[(interface_ip, '0.0.0.0')].area = service_area.identifier


def xe_ospf_redistribution_program_service(self, table_connections) -> None:
    """
    Program service for xe NED features
    """
    self.log.info(f'{self.device_name} OSPF redistribution')
    for service_table_connection in table_connections:
        for service_table_connection_ospf in table_connections[service_table_connection]['destination_protocols'][
            'OSPF']:
            if service_table_connection_ospf['src-protocol'] == 'oc-pol-types:STATIC' and \
                    service_table_connection_ospf['address-family'] == 'oc-types:IPV4':
                self.root.devices.device[self.device_name].config.ios__router.ospf[
                    service_table_connection_ospf['dst-protocol-process-number']].redistribute.static.create()
                if service_table_connection_ospf['import-policy']:
                    self.root.devices.device[self.device_name].config.ios__router.ospf[
                        service_table_connection_ospf['dst-protocol-process-number']].redistribute.static.route_map = \
                        service_table_connection_ospf['import-policy']
            elif service_table_connection_ospf['src-protocol'] == 'oc-pol-types:DIRECTLY_CONNECTED' and \
                    service_table_connection_ospf['address-family'] == 'oc-types:IPV4':
                self.root.devices.device[self.device_name].config.ios__router.ospf[
                    service_table_connection_ospf['dst-protocol-process-number']].redistribute.connected.create()
                if service_table_connection_ospf['import-policy']:
                    self.root.devices.device[self.device_name].config.ios__router.ospf[
                        service_table_connection_ospf['dst-protocol-process-number']].redistribute.connected.route_map = \
                        service_table_connection_ospf['import-policy']

            if service_table_connection_ospf['src-protocol'] == 'oc-pol-types:BGP' and service_table_connection_ospf[
                'address-family'] == 'oc-types:IPV4':
                self.root.devices.device[self.device_name].config.ios__router.ospf[
                    service_table_connection_ospf['dst-protocol-process-number']].redistribute.bgp.as_no = \
                        service_table_connection_ospf['src-protocol-process-number']
                if service_table_connection_ospf['import-policy']:
                    self.root.devices.device[self.device_name].config.ios__router.ospf[
                        service_table_connection_ospf['dst-protocol-process-number']].redistribute.bgp.route_map = \
                            service_table_connection_ospf['import-policy']

            if service_table_connection_ospf['src-protocol'] == 'oc-pol-types:OSPF' and service_table_connection_ospf[
                'address-family'] == 'oc-types:IPV4':
                self.root.devices.device[self.device_name].config.ios__router.ospf[
                    service_table_connection_ospf['dst-protocol-process-number']].redistribute.ospf.create(
                    service_table_connection_ospf['src-protocol-process-number'])
                if service_table_connection_ospf['import-policy']:
                    self.root.devices.device[self.device_name].config.ios__router.ospf[
                        service_table_connection_ospf['dst-protocol-process-number']].redistribute.ospf[
                        service_table_connection_ospf['src-protocol-process-number']].route_map = \
                        service_table_connection_ospf['import-policy']
            elif service_table_connection_ospf['src-protocol'] == 'oc-pol-types:ISIS' and service_table_connection_ospf[
                'address-family'] == 'oc-types:IPV4':
                pass
