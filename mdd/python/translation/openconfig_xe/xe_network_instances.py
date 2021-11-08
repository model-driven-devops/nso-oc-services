# -*- mode: python; python-indent: 4 -*-
import ipaddress
import re
from typing import Tuple

from translation.openconfig_xe.common import xe_get_interface_type_and_number
from translation.openconfig_xe.common import xe_system_get_interface_ip_address
from translation.openconfig_xe.xe_bgp import xe_bgp_global_program_service
from translation.openconfig_xe.xe_bgp import xe_bgp_neighbors_program_service
from translation.openconfig_xe.xe_bgp import xe_bgp_peer_groups_program_service


def xe_network_instances_program_service(self) -> None:
    """
    Program service for xe NED features
    """
    xe_configure_vrfs(self)
    xe_reconcile_vrf_interfaces(self)
    xe_configure_mpls(self)
    xe_configure_protocols(self)


def xe_configure_vrfs(self) -> None:
    """
    Ensure VRF with correct address families is on the device
    """
    for network_instance in self.service.oc_netinst__network_instances.network_instance:
        if network_instance.config.type != 'oc-ni-types:DEFAULT_INSTANCE':
            # Get VRFs from device cdb
            vrfs_device_db = list()
            for v in self.root.devices.device[self.device_name].config.ios__vrf.definition:
                vrfs_device_db.append(v.name)
            self.log.info(f'{self.device_name} VRFs in device {self.device_name} CDB: {vrfs_device_db}')

            # Create VRF in device
            if (network_instance.name not in vrfs_device_db) and (network_instance.config.type == 'oc-ni-types:L3VRF'):
                self.root.devices.device[self.device_name].config.ios__vrf.definition.create(network_instance.name)

            # Get address families for VRF from incoming configs
            vrf_address_families_in_model_configs = list()
            for af in network_instance.config.enabled_address_families:
                vrf_address_families_in_model_configs.append(af)

            # Create/delete address family presence containers as needed
            if self.root.devices.device[self.device_name].config.ios__vrf.definition[
                network_instance.name].address_family.ipv4.exists():
                if 'IPV4' not in vrf_address_families_in_model_configs:
                    del self.root.devices.device[self.device_name].config.ios__vrf.definition[
                        network_instance.name].address_family.ipv4
            elif 'IPV4' in vrf_address_families_in_model_configs:
                self.root.devices.device[self.device_name].config.ios__vrf.definition[
                    network_instance.name].address_family.ipv4.create()

            if self.root.devices.device[self.device_name].config.ios__vrf.definition[
                network_instance.name].address_family.ipv6.exists():
                if 'IPV6' not in vrf_address_families_in_model_configs:
                    del self.root.devices.device[self.device_name].config.ios__vrf.definition[
                        network_instance.name].address_family.ipv6
            elif 'IPV6' in vrf_address_families_in_model_configs:
                self.root.devices.device[self.device_name].config.ios__vrf.definition[
                    network_instance.name].address_family.ipv6.create()

            # Add route distinguisher
            if network_instance.config.route_distinguisher:
                self.root.devices.device[self.device_name].config.ios__vrf.definition[
                    network_instance.name].rd = network_instance.config.route_distinguisher

            # Add route targets
            # Get import route-targets from configs
            rt_import_config = [rt for rt in network_instance.config.route_targets_import]
            # Get export route-targets from configs
            rt_export_config = [rt for rt in network_instance.config.route_targets_export]

            # Get import route-targets from the CDB
            rt_import_cdb = [rt for rt in self.root.devices.device[self.device_name].config.ios__vrf.definition[
                network_instance.name].route_target.ios__import]
            # Get export route-targets from the CDB
            rt_export_cdb = [rt for rt in self.root.devices.device[self.device_name].config.ios__vrf.definition[
                network_instance.name].route_target.export]

            # Find route targets to create in CDB
            rt_import_to_cdb = [rt for rt in rt_import_config if rt not in set(rt_import_cdb)]
            rt_export_to_cdb = [rt for rt in rt_export_config if rt not in set(rt_export_cdb)]

            # Add Route Targets to CDB
            for rt in rt_import_to_cdb:
                self.root.devices.device[self.device_name].config.ios__vrf.definition[
                    network_instance.name].route_target.ios__import.create(rt)
            for rt in rt_export_to_cdb:
                self.root.devices.device[self.device_name].config.ios__vrf.definition[
                    network_instance.name].route_target.export.create(rt)


def xe_reconcile_vrf_interfaces(self) -> None:
    """
    Ensure device interfaces are in appropriate VRFs
    """
    for network_instance in self.service.oc_netinst__network_instances.network_instance:
        # interfaces in default route table are marked None, else their VRF name
        if network_instance.config.type == 'oc-ni-types:DEFAULT_INSTANCE':
            # Get interfaces from configs
            vrf_interfaces_in_model_configs = dict()
            for a in network_instance.interfaces.interface:
                vrf_interfaces_in_model_configs[a.id] = None
            self.log.info(
                f'{self.device_name} Interfaces in VRF configuration: {vrf_interfaces_in_model_configs}')
        else:
            # Get interfaces from configs
            vrf_interfaces_in_model_configs = dict()
            for a in network_instance.interfaces.interface:
                vrf_interfaces_in_model_configs[a.id] = network_instance.name
            self.log.info(
                f'{self.device_name} Interfaces in VRF configuration: {vrf_interfaces_in_model_configs}')

        # Get interfaces from CDB
        vrf_interfaces_in_cdb = xe_get_all_interfaces(self)
        self.log.info(
            f'{self.device_name} These are the interfaces VRFs from cdb: {vrf_interfaces_in_cdb}')

        # Assign interfaces to correct VRFs
        for i in vrf_interfaces_in_cdb:
            try:
                interface_type, interface_number = xe_get_interface_type_number_and_subinterface(i[0])
                class_attribute = getattr(self.root.devices.device[self.device_name].config.ios__interface,
                                          interface_type)
                interface = class_attribute[interface_number]

                if i[0] in vrf_interfaces_in_model_configs:
                    config_vrf = vrf_interfaces_in_model_configs[i[0]]
                    self.log.info(
                        f'{self.device_name} Configuring vrf.forwarding: {config_vrf}  {interface_type, interface_number}')
                    interface.vrf.forwarding = config_vrf
            except Exception as e:
                self.log.error(
                    f'{self.device_name} Failed to ensure VRF configs for interface {interface_type, interface_number}')
                self.log.info(f'{self.device_name} interface vrf failure traceback: {e}')


def xe_configure_mpls(self) -> None:
    """
    Configures the mpls section of openconfig-network-instance
    """
    for network_instance in self.service.oc_netinst__network_instances.network_instance:
        if network_instance.mpls.oc_netinst__global.config:
            if network_instance.mpls.oc_netinst__global.config.ttl_propagation is False:
                self.root.devices.device[
                    self.device_name].config.ios__mpls.mpls_ip_conf.ip.propagate_ttl_conf.propagate_ttl = 'false'
            elif network_instance.mpls.oc_netinst__global.config.ttl_propagation:
                self.root.devices.device[
                    self.device_name].config.ios__mpls.mpls_ip_conf.ip.propagate_ttl_conf.propagate_ttl = 'true'
        if network_instance.mpls.oc_netinst__global.interface_attributes.interface:
            self.root.devices.device[self.device_name].config.ios__mpls.ip = 'true'
            for interface in network_instance.mpls.oc_netinst__global.interface_attributes.interface:
                if interface.config.mpls_enabled:
                    interface_type, interface_number = xe_get_interface_type_and_number(
                        interface.interface_ref.config.interface)
                    class_attribute = getattr(self.root.devices.device[self.device_name].config.ios__interface,
                                              interface_type)
                    if interface.interface_ref.config.subinterface == 0:
                        interface_cdb = class_attribute[interface_number]
                    else:
                        interface_cdb = class_attribute[
                            f'{interface_number}.{interface.interface_ref.config.subinterface}']
                    if not interface_cdb.mpls.ip.exists():
                        interface_cdb.mpls.ip.create()
                elif interface.config.mpls_enabled is False:
                    interface_type, interface_number = xe_get_interface_type_and_number(
                        interface.interface_ref.config.interface)
                    class_attribute = getattr(self.root.devices.device[self.device_name].config.ios__interface,
                                              interface_type)
                    if interface.interface_ref.config.subinterface == 0:
                        interface_cdb = class_attribute[interface_number]
                    if interface_cdb.mpls.ip.exists():
                        interface_cdb.mpls.ip.delete()
        if network_instance.mpls.signaling_protocols:
            if network_instance.mpls.signaling_protocols.ldp:
                xe_configure_mpls_signaling_protocols_ldp(self, network_instance)


def xe_configure_mpls_signaling_protocols_ldp(self, service_network_instance) -> None:
    """
    Configures LDP
    """
    if service_network_instance.mpls.signaling_protocols.ldp.oc_netinst__global.config.lsr_id:
        ip_name_dict = xe_system_get_interface_ip_address(self)
        self.root.devices.device[self.device_name].config.ios__mpls.ldp.router_id.interface = ip_name_dict.get(
            service_network_instance.mpls.signaling_protocols.ldp.oc_netinst__global.config.lsr_id)
        self.root.devices.device[self.device_name].config.ios__mpls.ldp.router_id.force.create()
    if service_network_instance.mpls.signaling_protocols.ldp.oc_netinst__global.graceful_restart.config.enabled:
        self.root.devices.device[
            self.device_name].config.ios__mpls.ldp.graceful_restart_enable.graceful_restart.create()
    if service_network_instance.mpls.signaling_protocols.ldp.interface_attributes.config.hello_holdtime:
        self.root.devices.device[
            self.device_name].config.ios__mpls.ldp.discovery.hello.holdtime = service_network_instance.mpls.signaling_protocols.ldp.interface_attributes.config.hello_holdtime
    if service_network_instance.mpls.signaling_protocols.ldp.interface_attributes.config.hello_interval:
        self.root.devices.device[
            self.device_name].config.ios__mpls.ldp.discovery.hello.interval = service_network_instance.mpls.signaling_protocols.ldp.interface_attributes.config.hello_interval


def xe_configure_protocols(self) -> None:
    """
    Configures the protocols section of openconfig-network-instance
    """
    instance_bgp_list = []
    for network_instance in self.service.oc_netinst__network_instances.network_instance:
        if network_instance.protocols.protocol:
            for p in network_instance.protocols.protocol:
                self.log.debug(f'protocol identifier: {p.identifier}')
                if p.identifier == 'oc-pol-types:STATIC':
                    device_route = self.root.devices.device[self.device_name].config.ios__ip.route
                    if network_instance.config.type == 'oc-ni-types:DEFAULT_INSTANCE':  # if global table
                        if p.static_routes.static:
                            for static in p.static_routes.static:
                                network = ipaddress.ip_network(static.prefix)
                                for nh in static.next_hops.next_hop:
                                    route = device_route.ip_route_forwarding_list.create(str(network.network_address),
                                                                                         str(network.netmask),
                                                                                         nh.config.next_hop)
                                    if nh.config.metric:
                                        route.metric = nh.config.metric
                    elif network_instance.config.type == 'oc-ni-types:L3VRF':  # if VRF table
                        if not device_route.vrf.exists(network_instance.name):
                            device_route.vrf.create(network_instance.name)
                        if p.static_routes.static:
                            for static in p.static_routes.static:
                                route_vrf = device_route.vrf[network_instance.name]
                                network = ipaddress.ip_network(static.prefix)
                                for nh in static.next_hops.next_hop:
                                    route = route_vrf.ip_route_forwarding_list.create(str(network.network_address),
                                                                                      str(network.netmask),
                                                                                      nh.config.next_hop)
                                    if nh.config.metric:
                                        route.metric = nh.config.metric

                # oc-ni-types:DEFAULT_INSTANCE must be processed before VRFs
                # Incoming order doesn't matter
                # Collect needed BGP instance information below
                if p.identifier == 'oc-pol-types:BGP':
                    instance_bgp_list.append((p, network_instance.config.type, network_instance.config.name))

    # Sort BGP instance information so oc-ni-types:DEFAULT_INSTANCE is first and process
    if instance_bgp_list:
        instance_bgp_list.sort(key=lambda x: x[1])
        self.log.info(f'{self.device_name} instance_bgp_list {instance_bgp_list}')

        # Always use 'ip bgp-community new-format'
        if not self.root.devices.device[self.device_name].config.ios__ip.bgp_community.new_format.exists():
            self.root.devices.device[self.device_name].config.ios__ip.bgp_community.new_format.create()

        for bgp_instance in instance_bgp_list:
            # bgp_instance = (service_bgp, network_instance.config.type, network_instance.config.name)
            xe_bgp_global_program_service(self, bgp_instance[0], bgp_instance[1], bgp_instance[2])
            xe_bgp_peer_groups_program_service(self, bgp_instance[0], bgp_instance[1], bgp_instance[2])
            xe_bgp_neighbors_program_service(self, bgp_instance[0], bgp_instance[1], bgp_instance[2])


def xe_get_interface_type_number_and_subinterface(interface: str) -> Tuple[str, str]:
    """
    Receive full interface name. Returns interface type and number.
    :param interface: full interface name
    :return: tuple of interface type, interface number.subinterface number
    """
    rt = re.search(r'\D+', interface)
    interface_name = rt.group(0)
    rn = re.search(r'[0-9]+(\/[0-9]+)*(\.[0-9]+)*', interface)
    interface_number = rn.group(0)
    return interface_name, interface_number


def xe_get_all_interfaces(self) -> list:
    """
    Returns a list of tuples, e.g.  [('GigabitEthernet1', None), ('GigabitEthernet4', 'abc')]
    """
    interfaces = list()
    device_config = self.root.devices.device[self.device_name].config
    for a in dir(device_config.ios__interface):
        if not a.startswith('__'):
            class_method = getattr(device_config.ios__interface, a)
            for c in class_method:
                try:
                    interfaces.append((str(c) + str(c.name), c.vrf.forwarding))
                except:
                    pass
    return interfaces
