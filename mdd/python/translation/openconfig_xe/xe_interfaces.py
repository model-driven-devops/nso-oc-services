# -*- mode: python; python-indent: 4 -*-
import ipaddress
import re

import ncs
from translation.openconfig_xe.common import xe_get_interface_type_and_number

speeds_oc_to_xe = {
    'SPEED_10MB': '10',
    'SPEED_100MB': '100',
    'SPEED_1GB': '1000',
    'SPEED_10GB': '10000'
}


def xe_interfaces_program_service(self) -> None:
    """
    Program service for xe NED features too complex for XML template.
    """
    xe_update_vlan_db(self)
    xe_process_interfaces(self)


def xe_update_vlan_db(self) -> None:
    """
    Ensure vlan is available for incoming configuration
    """

    # Get VLANs from device VLAN DB
    vlans_device_db = list()
    for v in self.root.devices.device[self.device_name].config.ios__vlan.vlan_list:
        vlans_device_db.append(v.id)
    self.log.info(f'{self.device_name} VLANs in device DB: {vlans_device_db}')

    # Get VLANs from incoming config
    vlans_in_model_configs = list()
    for interface in self.service.oc_if__interfaces.interface:
        if interface.aggregation.switched_vlan.config.access_vlan:
            vlans_in_model_configs.append(interface.aggregation.switched_vlan.config.access_vlan)
        for x in interface.aggregation.switched_vlan.config.trunk_vlans:
            if x:
                vlans_in_model_configs.append(x)
        for x in interface.ethernet.switched_vlan.config.trunk_vlans:
            if x:
                vlans_in_model_configs.append(x)
        if interface.ethernet.switched_vlan.config.native_vlan:
            vlans_in_model_configs.append(interface.ethernet.switched_vlan.config.native_vlan)
        if interface.routed_vlan.config.vlan:
            vlans_in_model_configs.append(interface.routed_vlan.config.vlan)
    self.log.info(f'{self.device_name} VLANs from configs: {vlans_in_model_configs}')

    # Find VLANs to create in device VLAN DB
    vlans_to_create_in_db = [v for v in vlans_in_model_configs if v not in set(vlans_device_db)]
    self.log.info(f'{self.device_name} vlans_to_create_in_db: {vlans_to_create_in_db}')

    # Create VLANs in device VLAN DB
    for v in vlans_to_create_in_db:
        self.root.devices.device[self.device_name].config.ios__vlan.vlan_list.create(v)
        vlan = self.root.devices.device[self.device_name].config.ios__vlan.vlan_list[v]
        if vlan.shutdown.exists():
            vlan.shutdown.delete()


def xe_process_interfaces(self) -> None:
    """
    Programs device interfaces as defined in model
    """
    for interface in self.service.oc_if__interfaces.interface:
        # Layer 3 VLAN interfaces
        if interface.config.type == 'ianaift:l3ipvlan':
            if not self.root.devices.device[self.device_name].config.ios__interface.Vlan.exists(
                    interface.routed_vlan.config.vlan):
                self.root.devices.device[self.device_name].config.ios__interface.Vlan.create(
                    interface.routed_vlan.config.vlan)

            vlan = self.root.devices.device[self.device_name].config.ios__interface.Vlan[
                interface.routed_vlan.config.vlan]
            if interface.config.description:
                vlan.description = interface.config.description
            if interface.config.enabled:
                if vlan.shutdown.exists():
                    vlan.shutdown.delete()
            else:
                if not vlan.shutdown.exists():
                    vlan.shutdown.create()
            if interface.config.mtu:
                vlan.mtu = interface.config.mtu
            xe_configure_ipv4(self, vlan, interface.routed_vlan.ipv4)

        # Layer 2 interfaces
        elif interface.config.type == 'ianaift:l2vlan' or (
                interface.config.type == 'ianaift:ethernetCsmacd' and interface.ethernet.config.aggregate_id):
            interface_type, interface_number = xe_get_interface_type_and_number(interface.config.name)
            class_attribute = getattr(self.root.devices.device[self.device_name].config.ios__interface,
                                      interface_type)
            l2_interface = class_attribute[interface_number]
            xe_interface_config(interface, l2_interface)
            xe_interface_hold_time(interface, l2_interface)
            xe_interface_ethernet(interface, l2_interface)

        # Port channels
        elif interface.config.type == 'ianaift:ieee8023adLag':
            port_channel_number = xe_get_port_channel_number(interface.name)
            if not self.root.devices.device[self.device_name].config.ios__interface.Port_channel.exists(
                    port_channel_number):
                self.root.devices.device[self.device_name].config.ios__interface.Port_channel.create(
                    port_channel_number)
            port_channel = self.root.devices.device[self.device_name].config.ios__interface.Port_channel[
                port_channel_number]
            xe_interface_config(interface, port_channel)
            xe_interface_hold_time(interface, port_channel)
            xe_interface_aggregation(self, interface, port_channel)

        # Physical and Sub-interfaces
        elif interface.config.type == 'ianaift:ethernetCsmacd' and interface.subinterfaces.subinterface:
            interface_type, interface_number = xe_get_interface_type_and_number(interface.config.name)
            class_attribute = getattr(self.root.devices.device[self.device_name].config.ios__interface,
                                      interface_type)
            physical_interface = class_attribute[interface_number]
            xe_interface_config(interface, physical_interface)
            xe_interface_hold_time(interface, physical_interface)
            xe_interface_ethernet(interface, physical_interface)
            for subinterface_service in interface.subinterfaces.subinterface:
                if subinterface_service.index != 0:
                    if not class_attribute.exists(f'{interface_number}.{subinterface_service.index}'):
                        class_attribute.create(f'{interface_number}.{subinterface_service.index}')
                    subinterface_cdb = class_attribute[f'{interface_number}.{subinterface_service.index}']
                    # If switchport tag, then remove
                    if subinterface_cdb.switchport.exists():
                        subinterface_cdb.switchport.delete()
                    # description
                    if subinterface_service.config.description:
                        subinterface_cdb.description = subinterface_service.config.description
                    # Remove switchport
                    if subinterface_cdb.switchport.exists():
                        subinterface_cdb.switchport.delete()
                    # enabled
                    if subinterface_service.config.enabled:
                        if subinterface_cdb.shutdown.exists():
                            subinterface_cdb.shutdown.delete()
                    else:
                        if not subinterface_cdb.shutdown.exists():
                            subinterface_cdb.shutdown.create()
                    subinterface_cdb.encapsulation.dot1Q.vlan_id = subinterface_service.vlan.config.vlan_id
                    xe_configure_ipv4(self, subinterface_cdb, subinterface_service.ipv4)
                else:  # IPv4 for main interface
                    # Remove switchport
                    if physical_interface.switchport.exists():
                        physical_interface.switchport.delete()
                    xe_configure_ipv4(self, physical_interface, subinterface_service.ipv4)

        # Loopback interfaces
        elif interface.config.type == 'ianaift:softwareLoopback':
            interface_type, interface_number = xe_get_interface_type_and_number(interface.config.name)
            if not self.root.devices.device[self.device_name].config.ios__interface.Loopback.exists(interface_number):
                self.root.devices.device[self.device_name].config.ios__interface.Loopback.create(interface_number)
            loopback = self.root.devices.device[self.device_name].config.ios__interface.Loopback[interface_number]
            xe_interface_config(interface, loopback)
            xe_configure_ipv4(self, loopback, interface.subinterfaces.subinterface[0].ipv4)

        # VASI interfaces
        elif interface.config.type == 'iftext:vasi':
            interface_type, interface_number = xe_get_interface_type_and_number(interface.config.name)
            class_attribute = getattr(self.root.devices.device[self.device_name].config.ios__interface,
                                      interface_type)
            if not class_attribute.exists(interface_number):
                class_attribute.create(interface_number)
            vasi_interface = class_attribute[interface_number]
            xe_interface_config(interface, vasi_interface)
            xe_configure_ipv4(self, vasi_interface, interface.subinterfaces.subinterface[0].ipv4)

        # GRE Tunnel interface
        elif interface.config.type == 'ianaift:tunnel':
            interface_type, interface_number = xe_get_interface_type_and_number(interface.config.name)
            class_attribute = getattr(self.root.devices.device[self.device_name].config.ios__interface,
                                      interface_type)
            if not class_attribute.exists(interface_number):
                class_attribute.create(interface_number)
            tunnel_interface = class_attribute[interface_number]
            xe_interface_config(interface, tunnel_interface)
            xe_configure_tunnel_interface(interface, tunnel_interface)
            xe_configure_ipv4(self, tunnel_interface, interface.oc_tun__tunnel.ipv4)
        else:
            raise ValueError(
                f'Interface type {interface.config.type} not supported by this NSO_OC_Services implementation. Please file an issue at https://github.com/model-driven-devops/nso-oc-services')


def xe_configure_tunnel_interface(interface_service: ncs.maagic.ListElement,
                                  interface_cdb: ncs.maagic.ListElement) -> None:
    if interface_service.oc_tun__tunnel.config.src:
        interface_cdb.tunnel.source = interface_service.oc_tun__tunnel.config.src
    if interface_service.oc_tun__tunnel.config.dst:
        interface_cdb.tunnel.destination = interface_service.oc_tun__tunnel.config.dst
    if interface_service.oc_tun__tunnel.config.gre_key:
        interface_cdb.tunnel.key = interface_service.oc_tun__tunnel.config.gre_key
    if interface_service.oc_tun__tunnel.config.oc_if_tun_ext__tunnel_path_mtu_discovery:
        interface_cdb.tunnel.path_mtu_discovery.create()
    elif interface_service.oc_tun__tunnel.config.oc_if_tun_ext__tunnel_path_mtu_discovery is False:
        if interface_cdb.tunnel.path_mtu_discovery.exists():
            interface_cdb.tunnel.path_mtu_discovery.delete()
    if interface_service.oc_tun__tunnel.config.oc_if_tun_ext__keepalives.oc_if_tun_ext__period and interface_service.oc_tun__tunnel.config.oc_if_tun_ext__keepalives.oc_if_tun_ext__retries:
        interface_cdb.keepalive_period_retries.keepalive.period = interface_service.oc_tun__tunnel.config.oc_if_tun_ext__keepalives.oc_if_tun_ext__period
        interface_cdb.keepalive_period_retries.keepalive.retries = interface_service.oc_tun__tunnel.config.oc_if_tun_ext__keepalives.oc_if_tun_ext__retries
    if interface_service.oc_tun__tunnel.config.ttl:
        raise ValueError('NSO XE CLI NED cisco-ios-cli-6.74 does not support Tunnel TTL')


def xe_get_subinterfaces(self) -> list:
    """
    Returns a list of existing subinterfaces
    """
    interfaces = list()
    device_config = self.root.devices.device[self.device_name].config
    for a in dir(device_config.ios__interface):
        if not a.startswith('__'):
            class_method = getattr(device_config.ios__interface, a)
            for i in class_method:
                try:
                    if '.' in str(i.name):
                        interfaces.append(str(i) + str(i.name))
                except:
                    pass
    return interfaces


def xe_interface_ethernet(interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement) -> None:
    # auto-negotiate
    if interface_service.ethernet.config.auto_negotiate:
        interface_cdb.negotiation.auto = interface_service.ethernet.config.auto_negotiate
    elif interface_service.ethernet.config.auto_negotiate is False:
        interface_cdb.negotiation.auto = interface_service.ethernet.config.auto_negotiate
        # port-speed - may need to be set before duplex is configured
        if interface_service.ethernet.config.port_speed:
            interface_cdb.speed = speeds_oc_to_xe.get(interface_service.ethernet.config.port_speed)
        # duplex-mode
        if interface_service.ethernet.config.duplex_mode:
            interface_cdb.duplex = str(interface_service.ethernet.config.duplex_mode).lower()
    # port-speed
    if interface_service.ethernet.config.port_speed:
        interface_cdb.speed = speeds_oc_to_xe.get(interface_service.ethernet.config.port_speed)
    # enable-flow-control
    if interface_service.ethernet.config.enable_flow_control is True:
        interface_cdb.flowcontrol.receive = 'on'
    elif interface_service.ethernet.config.enable_flow_control is False:
        interface_cdb.flowcontrol.receive = None
    # mac-address
    if interface_service.ethernet.config.mac_address:
        xe_mac = f'{interface_service.ethernet.config.mac_address[0:2]}{interface_service.ethernet.config.mac_address[3:5]}.{interface_service.ethernet.config.mac_address[6:8]}{interface_service.ethernet.config.mac_address[9:11]}.{interface_service.ethernet.config.mac_address[12:14]}{interface_service.ethernet.config.mac_address[15:17]}'
        interface_cdb.mac_address = xe_mac
    # # poe  TODO
    # if interface_service.ethernet.poe.config.enabled is True:
    #     interface_cdb.power.inline.mode = 'auto'
    # elif interface_service.ethernet.poe.config.enabled is False:
    #     interface_cdb.power.inline.mode = 'never'

    # switched-vlan interface-mode
    if interface_service.ethernet.switched_vlan.config.interface_mode:
        xe_configure_switched_vlan(interface_cdb, interface_service.ethernet.switched_vlan)
    else:
        if interface_cdb.switchport.exists():
            interface_cdb.switchport.delete()
    if interface_service.ethernet.config.aggregate_id:
        interface_cdb.channel_group.number = xe_get_port_channel_number(
            interface_service.ethernet.config.aggregate_id)
        interface_cdb.channel_group.mode = 'active'


def xe_interface_aggregation(s, interface_service: ncs.maagic.ListElement,
                             interface_cdb: ncs.maagic.ListElement) -> None:
    if interface_service.aggregation.config.min_links:
        interface_cdb.port_channel.min_links = int(interface_service.aggregation.config.min_links)

    # switched-vlan interface-mode
    if interface_service.aggregation.switched_vlan.config.interface_mode:
        xe_configure_switched_vlan(interface_cdb, interface_service.aggregation.switched_vlan)
    else:
        if interface_cdb.switchport.exists():
            interface_cdb.switchport.delete()
    if interface_service.aggregation.ipv4.addresses.address:
        xe_configure_ipv4(s, interface_cdb, interface_service.aggregation.ipv4)


def xe_configure_ipv4(s, interface_cdb: ncs.maagic.ListElement, service_ipv4: ncs.maagic.Container) -> None:
    """
    Configures openconfig-if-ip ipv4-top
    """
    # Get current cdb addresses
    ips_and_masks_cdb = list()
    for x in interface_cdb.ip.address.secondary:
        ips_and_masks_cdb.append((x.address, x.mask))

    # Create service config address mask list
    ips_and_masks = list()
    if service_ipv4.addresses.address:
        if interface_cdb.ip.address.dhcp.exists():
            interface_cdb.ip.address.dhcp.delete()
        for a in service_ipv4.addresses.address:
            ip = ipaddress.ip_network(f'10.0.0.0/{a.config.prefix_length}')
            ips_and_masks.append((a.config.ip, str(ip.netmask)))

        # Remove unrequested IPs from CDB
        ips_to_remove = list()
        for ips in ips_and_masks_cdb:
            if ips not in ips_and_masks[1:]:
                ips_to_remove.append(ips)
        for ips in ips_to_remove:
            del interface_cdb.ip.address.secondary[ips]

        # Update/Create needed IP addresses in CDB
        for counter, ip_mask in enumerate(ips_and_masks):
            if counter == 0:
                interface_cdb.ip.address.primary.address = ip_mask[0]
                interface_cdb.ip.address.primary.mask = ip_mask[1]
            # elif counter > 0: TODO
            #     if not interface_cdb.ip.address.secondary.exists(ip_mask):
            #         interface_cdb.ip.address.secondary.create(ip_mask)
    else:
        if service_ipv4.config.dhcp_client:
            interface_cdb.ip.address.dhcp.create()
    if service_ipv4.config.dhcp_client is False:
        if interface_cdb.ip.address.dhcp.exists():
            interface_cdb.ip.address.dhcp.delete()
    # ip mtu
    if service_ipv4.config.mtu:
        interface_cdb.ip.mtu = service_ipv4.config.mtu
    # adjust TCP MSS
    if service_ipv4.config.oc_if_ip_mdd_ext__tcp_adjust_mss:
        interface_cdb.ip.tcp.adjust_mss = service_ipv4.config.oc_if_ip_mdd_ext__tcp_adjust_mss
    # no ip redirects
    if service_ipv4.config.oc_if_ip_mdd_ext__redirects:
        interface_cdb.ip.redirects = True
    elif service_ipv4.config.oc_if_ip_mdd_ext__redirects is False:
        interface_cdb.ip.redirects = False
    # no ip unreachables
    if service_ipv4.config.oc_if_ip_mdd_ext__unreachables:
        interface_cdb.ip.unreachables = True
    elif service_ipv4.config.oc_if_ip_mdd_ext__unreachables is False:
        interface_cdb.ip.unreachables = False
    # proxy-arp
    if service_ipv4.proxy_arp.config.mode == 'DISABLE':
        interface_cdb.ip.proxy_arp = False
    if service_ipv4.proxy_arp.config.mode == 'REMOTE_ONLY':
        interface_cdb.ip.proxy_arp = True

    # VRRP
    for a in service_ipv4.addresses.address:
        if hasattr(a, 'vrrp'):
            if a.vrrp.vrrp_group:
                for v in a.vrrp.vrrp_group:
                    if not interface_cdb.vrrp.exists(v.virtual_router_id):
                        interface_cdb.vrrp.create(v.virtual_router_id)
                    vrrp_group = interface_cdb.vrrp[v.virtual_router_id]
                    # accept_mode TODO
                    # priority
                    if v.config.priority:
                        vrrp_group.priority = v.config.priority
                    # preempt
                    if v.config.preempt:
                        if v.config.preempt_delay:
                            vrrp_group.preempt.delay.minimum = v.config.preempt_delay
                        else:
                            vrrp_group.preempt.delay.minimum = 0
                    # virtual address
                    if v.config.virtual_address:
                        for counter, address in enumerate(v.config.virtual_address):
                            if counter == 0:
                                vrrp_group.ip.address = address
                            # else:  TODO add secondaries
                            #     vrrp_group.ip.secondary_address.create(address)
                    if v.config.advertisement_interval:
                        vrrp_group.timers.advertise.seconds = v.config.advertisement_interval // 100  # oc-ip uses centiseconds
                    # VRRP interface tracking TODO


def xe_configure_switched_vlan(interface_cdb: ncs.maagic.ListElement,
                               service_switched_vlan: ncs.maagic.Container) -> None:
    """
    Configures openconfig-vlan vlan-switched-top
    """

    if service_switched_vlan.config.interface_mode == 'TRUNK':
        if not interface_cdb.switchport.exists():
            interface_cdb.switchport.create()
        interface_cdb.switchport.trunk.encapsulation = 'dot1q'
        if not interface_cdb.switchport.mode.trunk.exists():
            interface_cdb.switchport.mode.trunk.create()
        if service_switched_vlan.config.native_vlan:
            interface_cdb.switchport.trunk.native.vlan = int(
                service_switched_vlan.config.native_vlan)
        elif service_switched_vlan.config.native_vlan == '':
            interface_cdb.switchport.trunk.native.vlan = None
        # Reconcile trunked VLANs
        allowed_vlans_cdb = [v for v in interface_cdb.switchport.trunk.allowed.vlan.vlans]
        allowed_vlans_config = [int(v) for v in service_switched_vlan.config.trunk_vlans]
        # Remove unspecified VLANs
        for v in allowed_vlans_cdb:
            if v not in allowed_vlans_config:
                interface_cdb.switchport.trunk.allowed.vlan.vlans.remove(v)
        # Added specified VLANs
        for v in allowed_vlans_config:
            if v not in allowed_vlans_cdb:
                interface_cdb.switchport.trunk.allowed.vlan.vlans.create(v)
    elif service_switched_vlan.config.interface_mode == 'ACCESS':
        if not interface_cdb.switchport.exists():
            interface_cdb.switchport.create()
        if not interface_cdb.switchport.mode.access.exists():
            interface_cdb.switchport.mode.access.create()
        if service_switched_vlan.config.access_vlan:
            interface_cdb.switchport.access.vlan = int(
                service_switched_vlan.config.access_vlan)


def xe_interface_config(interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement) -> None:
    # description
    if interface_service.config.description:
        interface_cdb.description = interface_service.config.description
    # enabled
    if interface_service.config.enabled:
        if interface_cdb.shutdown.exists():
            interface_cdb.shutdown.delete()
    else:
        if not interface_cdb.shutdown.exists():
            interface_cdb.shutdown.create()
    # # loopback-mode  TODO
    # if interface_service.config.loopback_mode:
    #     pass
    # mtu
    if interface_service.config.mtu:
        interface_cdb.mtu = interface_service.config.mtu


def xe_interface_hold_time(interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement) -> None:
    if interface_service.hold_time.config.down:
        interface_cdb.carrier_delay.msec = int(interface_service.hold_time.config.down)
    if interface_service.hold_time.config.up:
        raise ValueError('interface hold-time up is not supported in XE')


def xe_get_port_channel_number(interface: str) -> int:
    pn = re.search(r'\d+', interface)
    return int(pn.group(0))
