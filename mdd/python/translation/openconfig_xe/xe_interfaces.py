# -*- mode: python; python-indent: 4 -*-
import ipaddress
import re

import ncs
from translation.common import get_interface_type_and_number

speeds_oc_to_xe = {
    'SPEED_10MB': '10',
    'SPEED_100MB': '100',
    'SPEED_1GB': '1000',
    'SPEED_10GB': '10000'
}


def xe_interfaces_program_service(self, nso_props) -> None:
    """
    Program service for xe NED features too complex for XML template.
    """
    xe_update_vlan_db(self, nso_props)
    xe_process_interfaces(self, nso_props)


def xe_update_vlan_db(self, nso_props) -> None:
    """
    Ensure vlan is available for incoming configuration
    """

    # Get VLANs from device VLAN DB
    vlans_device_db = list()
    for v in nso_props.root.devices.device[nso_props.device_name].config.ios__vlan.vlan_list:
        vlans_device_db.append(v.id)
    self.log.info(f'{nso_props.device_name} VLANs in device DB: {vlans_device_db}')

    # Get VLANs from incoming config
    vlans_in_model_configs = list()
    for interface in nso_props.service.oc_if__interfaces.interface:
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
    self.log.info(f'{nso_props.device_name} VLANs from configs: {vlans_in_model_configs}')

    # Find VLANs to create in device VLAN DB
    vlans_to_create_in_db = [v for v in vlans_in_model_configs if v not in set(vlans_device_db)]
    self.log.info(f'{nso_props.device_name} vlans_to_create_in_db: {vlans_to_create_in_db}')

    # Create VLANs in device VLAN DB
    for v in vlans_to_create_in_db:
        nso_props.root.devices.device[nso_props.device_name].config.ios__vlan.vlan_list.create(v)
        vlan = nso_props.root.devices.device[nso_props.device_name].config.ios__vlan.vlan_list[v]
        if vlan.shutdown.exists():
            vlan.shutdown.delete()


def check_for_ipv6(nso_props):
    """
    Is IPv6 being used?
    """
    for interface in nso_props.service.oc_if__interfaces.interface:
        for sub_if in interface.subinterfaces.subinterface:
            if sub_if.oc_ip__ipv6.addresses.address:
                return True
        if interface.oc_tun__tunnel.ipv6.addresses.address:
            return True
        if interface.config.type == 'ianaift:ieee8023adLag':
            if interface.oc_lag__aggregation.oc_ip__ipv6.config.dhcp_client or \
                    interface.oc_lag__aggregation.oc_ip__ipv6.addresses.address:
                return True
    return False


def xe_process_interfaces(self, nso_props) -> None:
    """
    Programs device interfaces as defined in model
    """
    routing_ipv6 = check_for_ipv6(nso_props)
    if routing_ipv6:
        nso_props.root.devices.device[nso_props.device_name].config.ios__ipv6.unicast_routing.create()
        nso_props.root.devices.device[nso_props.device_name].config.ios__fhrp.version.vrrp = 'v3'
    for interface in nso_props.service.oc_if__interfaces.interface:
        # Layer 3 VLAN interfaces
        if interface.config.type == 'ianaift:l3ipvlan':
            if not nso_props.root.devices.device[nso_props.device_name].config.ios__interface.Vlan.exists(
                    interface.routed_vlan.config.vlan):
                nso_props.root.devices.device[nso_props.device_name].config.ios__interface.Vlan.create(
                    interface.routed_vlan.config.vlan)

            vlan = nso_props.root.devices.device[nso_props.device_name].config.ios__interface.Vlan[
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
            xe_configure_hsrp_v1(self, vlan, interface.routed_vlan.ipv4)
            xe_configure_ipv6(self, vlan, interface.routed_vlan.ipv6)
            if routing_ipv6:
                xe_configure_vrrp_v3(self, vlan, interface.routed_vlan.ipv4, 'ipv4')
                xe_configure_vrrp_v3(self, vlan, interface.routed_vlan.ipv6, 'ipv6')
            else:
                xe_configure_vrrp_v2_legacy(self, vlan, interface.routed_vlan.ipv4)

        # Layer 2 interfaces
        elif interface.config.type == 'ianaift:l2vlan' or (
                interface.config.type == 'ianaift:ethernetCsmacd' and interface.ethernet.config.aggregate_id):
            interface_type, interface_number = get_interface_type_and_number(interface.config.name)
            class_attribute = getattr(nso_props.root.devices.device[nso_props.device_name].config.ios__interface,
                                      interface_type)
            l2_interface = class_attribute[interface_number]
            xe_interface_config(interface, l2_interface)
            xe_interface_hold_time(interface, l2_interface)
            xe_interface_ethernet(self, nso_props, interface, l2_interface)
            xe_interface_storm_control(interface, l2_interface)

        # Port channels
        elif interface.config.type == 'ianaift:ieee8023adLag':
            interface_type, interface_number = get_interface_type_and_number(interface.config.name)
            class_attribute = getattr(nso_props.root.devices.device[nso_props.device_name].config.ios__interface,
                                      interface_type)
            if not class_attribute.exists(interface_number):
                class_attribute.create(interface_number)
            port_channel = class_attribute[interface_number]
            xe_interface_config(interface, port_channel)
            xe_interface_hold_time(interface, port_channel)
            if len(interface.subinterfaces.subinterface) == 0:
                xe_interface_aggregation(self, nso_props, interface, port_channel, routing_ipv6)
            else:
                for subinterface_service in interface.subinterfaces.subinterface:
                    if subinterface_service.index != 0:
                        class_attribute_sub_if = nso_props.root.devices.device[
                            nso_props.device_name].config.ios__interface.Port_channel_subinterface.Port_channel
                        if not class_attribute_sub_if.exists(f'{interface_number}.{subinterface_service.index}'):
                            class_attribute_sub_if.create(f'{interface_number}.{subinterface_service.index}')
                        subinterface_cdb = class_attribute_sub_if[f'{interface_number}.{subinterface_service.index}']
                        # If switchport tag, then remove
                        if subinterface_cdb.switchport.exists():
                            subinterface_cdb.switchport.delete()
                        # description
                        if subinterface_service.config.description:
                            subinterface_cdb.description = subinterface_service.config.description
                        # enabled
                        if subinterface_service.config.enabled:
                            if subinterface_cdb.shutdown.exists():
                                subinterface_cdb.shutdown.delete()
                        else:
                            if not subinterface_cdb.shutdown.exists():
                                subinterface_cdb.shutdown.create()
                        subinterface_cdb.encapsulation.dot1Q.vlan_id = subinterface_service.vlan.config.vlan_id
                        xe_configure_ipv4(self, subinterface_cdb, subinterface_service.ipv4)
                        xe_configure_hsrp_v1(self, subinterface_cdb, subinterface_service.ipv4)
                        xe_configure_ipv6(self, subinterface_cdb, subinterface_service.ipv6)
                        if routing_ipv6:
                            xe_configure_vrrp_v3(self, subinterface_cdb, subinterface_service.ipv4, 'ipv4')
                            xe_configure_vrrp_v3(self, subinterface_cdb, subinterface_service.ipv6, 'ipv6')
                        else:
                            xe_configure_vrrp_v2_legacy(self, subinterface_cdb, subinterface_service.ipv4)
                    else:  # IPv4 for main interface
                        # Remove switchport
                        if physical_interface.switchport.exists():
                            physical_interface.switchport.delete()
                        xe_interface_aggregation(self, interface, port_channel, routing_ipv6)

        # Physical and Sub-interfaces
        elif interface.config.type == 'ianaift:ethernetCsmacd':
            interface_type, interface_number = get_interface_type_and_number(interface.config.name)
            class_attribute = getattr(nso_props.root.devices.device[nso_props.device_name].config.ios__interface,
                                      interface_type)
            physical_interface = class_attribute[interface_number]
            xe_interface_config(interface, physical_interface)
            xe_interface_hold_time(interface, physical_interface)
            xe_interface_storm_control(interface, physical_interface)
            if interface.ethernet.switched_vlan.config.interface_mode:
                raise ValueError(
                    f"Interface {interface_type}{interface_number} is configured a type \
                    'ethernetCSMACD'. It should be type 'l2vlan' when configured as a \
                    {interface.ethernet.switched_vlan.config.interface_mode} port.")
            xe_interface_ethernet(self, nso_props, interface, physical_interface)
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
                    xe_configure_hsrp_v1(self, subinterface_cdb, subinterface_service.ipv4)
                    xe_configure_ipv6(self, subinterface_cdb, subinterface_service.ipv6)
                    if routing_ipv6:
                        xe_configure_vrrp_v3(self, subinterface_cdb, subinterface_service.ipv4, 'ipv4')
                        xe_configure_vrrp_v3(self, subinterface_cdb, subinterface_service.ipv6, 'ipv6')
                    else:
                        xe_configure_vrrp_v2_legacy(self, subinterface_cdb, subinterface_service.ipv4)
                else:  # IPv4 for main interface
                    # Remove switchport
                    if physical_interface.switchport.exists():
                        physical_interface.switchport.delete()
                    xe_configure_ipv4(self, physical_interface, subinterface_service.ipv4)
                    xe_configure_hsrp_v1(self, physical_interface, subinterface_service.ipv4)
                    xe_configure_ipv6(self, physical_interface, subinterface_service.ipv6)
                    if routing_ipv6:
                        xe_configure_vrrp_v3(self, physical_interface, subinterface_service.ipv4, 'ipv4')
                        xe_configure_vrrp_v3(self, physical_interface, subinterface_service.ipv6, 'ipv6')
                    else:
                        xe_configure_vrrp_v2_legacy(self, physical_interface, subinterface_service.ipv4)

        # Loopback interfaces
        elif interface.config.type == 'ianaift:softwareLoopback':
            interface_type, interface_number = get_interface_type_and_number(interface.config.name)
            if not nso_props.root.devices.device[nso_props.device_name].config.ios__interface.Loopback.exists(interface_number):
                nso_props.root.devices.device[nso_props.device_name].config.ios__interface.Loopback.create(interface_number)
            loopback = nso_props.root.devices.device[nso_props.device_name].config.ios__interface.Loopback[interface_number]
            xe_interface_config(interface, loopback)
            xe_configure_ipv4(self, loopback, interface.subinterfaces.subinterface[0].ipv4)
            xe_configure_ipv6(self, loopback, interface.subinterfaces.subinterface[0].ipv6)

        # VASI interfaces
        elif interface.config.type == 'iftext:vasi':
            interface_type, interface_number = get_interface_type_and_number(interface.config.name)
            class_attribute = getattr(nso_props.root.devices.device[nso_props.device_name].config.ios__interface,
                                      interface_type)
            if not class_attribute.exists(interface_number):
                class_attribute.create(interface_number)
            vasi_interface = class_attribute[interface_number]
            xe_interface_config(interface, vasi_interface)
            xe_configure_ipv4(self, vasi_interface, interface.subinterfaces.subinterface[0].ipv4)
            xe_configure_ipv6(self, vasi_interface, interface.subinterfaces.subinterface[0].ipv6)

        # GRE Tunnel interface
        elif interface.config.type == 'ianaift:tunnel':
            interface_type, interface_number = get_interface_type_and_number(interface.config.name)
            class_attribute = getattr(nso_props.root.devices.device[nso_props.device_name].config.ios__interface,
                                      interface_type)
            if not class_attribute.exists(interface_number):
                class_attribute.create(interface_number)
            tunnel_interface = class_attribute[interface_number]
            xe_interface_config(interface, tunnel_interface)
            xe_configure_tunnel_interface(interface, tunnel_interface)
            xe_configure_ipv4(self, tunnel_interface, interface.oc_tun__tunnel.ipv4)
            xe_configure_ipv6(self, tunnel_interface, interface.oc_tun__tunnel.ipv6)
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


def xe_get_subinterfaces(self, nso_props) -> list:
    """
    Returns a list of existing subinterfaces
    """
    interfaces = list()
    device_config = nso_props.root.devices.device[nso_props.device_name].config
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


def xe_interface_ethernet(self, nso_props, interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement) -> None:
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
        xe_configure_switched_vlan(self, nso_props, interface_cdb, interface_service.ethernet.switched_vlan)
    else:
        if interface_cdb.switchport.exists():
            interface_cdb.switchport.delete()
    if interface_service.ethernet.config.aggregate_id:
        interface_cdb.channel_group.number = xe_get_port_channel_number(
            interface_service.ethernet.config.aggregate_id)
        interface_cdb.channel_group.mode = 'active'


def xe_interface_aggregation(self, nso_props, interface_service: ncs.maagic.ListElement,
                             interface_cdb: ncs.maagic.ListElement, ipv6: bool) -> None:
    if interface_service.aggregation.config.min_links:
        interface_cdb.port_channel.min_links = int(interface_service.aggregation.config.min_links)

    # switched-vlan interface-mode
    if interface_service.aggregation.switched_vlan.config.interface_mode:
        xe_configure_switched_vlan(self, nso_props, interface_cdb, interface_service.aggregation.switched_vlan)
    else:
        if interface_cdb.switchport.exists():
            interface_cdb.switchport.delete()
    if interface_service.aggregation.ipv4.addresses.address:
        xe_configure_ipv4(self, interface_cdb, interface_service.aggregation.ipv4)
        xe_configure_hsrp_v1(self, interface_cdb, interface_service.aggregation.ipv4)
        xe_configure_ipv6(self, interface_cdb, interface_service.aggregation.ipv6)
        if ipv6:
            xe_configure_vrrp_v3(self, interface_cdb, interface_service.aggregation.ipv4, 'ipv4')
            xe_configure_vrrp_v3(self, interface_cdb, interface_service.aggregation.ipv6, 'ipv6')
        else:
            xe_configure_vrrp_v2_legacy(self, interface_cdb, interface_service.aggregation.ipv4)


def xe_configure_ipv4(self, interface_cdb: ncs.maagic.ListElement, service_ipv4: ncs.maagic.Container) -> None:
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
    # reply-mask
    if service_ipv4.config.oc_if_ip_mdd_ext__mask_reply:
        interface_cdb.ip.mask_reply.create()
    elif service_ipv4.config.oc_if_ip_mdd_ext__mask_reply is False:
        if interface_cdb.ip.mask_reply.exists():
            interface_cdb.ip.mask_reply.delete()
    # NAT interface
    if service_ipv4.config.oc_if_ip_mdd_ext__nat.nat_choice == 'inside':
        interface_cdb.ip.nat.inside.create()
    elif service_ipv4.config.oc_if_ip_mdd_ext__nat.nat_choice == 'outside':
        interface_cdb.ip.nat.outside.create()
    elif service_ipv4.config.oc_if_ip_mdd_ext__nat.nat_choice == 'disabled':
        if interface_cdb.ip.nat.inside.exists():
            interface_cdb.ip.nat.inside.delete()
        elif interface_cdb.ip.nat.outside.exists():
            interface_cdb.ip.nat.outside.delete()


def xe_configure_ipv6(self, interface_cdb: ncs.maagic.ListElement, service_ipv6: ncs.maagic.Container) -> None:
    """
    Configures openconfig-if-ip ipv6-top
    """
    # Get current cdb prefixes
    prefixes_cdb = list()
    for x in interface_cdb.ipv6.address.prefix_list:
        prefixes_cdb.append(x.prefix.upper())
    # Create service config prefixes list
    prefixes_service = list()
    if len(service_ipv6.addresses.address) > 0:
        if interface_cdb.ipv6.address.dhcp.exists():
            interface_cdb.ipv6.address.dhcp.delete()
        for a in service_ipv6.addresses.address:
            prefixes_service.append(f"{a.config.ip.upper()}/{str(a.config.prefix_length)}")

        # Remove unrequested Prefixes from CDB
        prefixes_to_remove = list()
        for prefix in prefixes_cdb:
            if prefix not in prefixes_service[1:]:
                prefixes_to_remove.append(prefix)
        for prefix in prefixes_to_remove:
            del interface_cdb.ipv6.address.prefix_list[prefix]

        # Update/Create needed IP prefixes in CDB
        for prefix in prefixes_service:
            interface_cdb.ipv6.address.prefix_list.create(prefix)
    else:
        if service_ipv6.config.dhcp_client:
            interface_cdb.ipv6.address.dhcp.create()
    if service_ipv6.config.dhcp_client is False:
        if interface_cdb.ipv6.address.dhcp.exists():
            interface_cdb.ipv6.address.dhcp.delete()
    # ip mtu
    if service_ipv6.config.mtu:
        interface_cdb.ipv6.mtu = service_ipv6.config.mtu
    # adjust TCP MSS
    if service_ipv6.config.oc_if_ip_mdd_ext__tcp_adjust_mss:
        interface_cdb.ipv6.tcp.adjust_mss = service_ipv6.config.oc_if_ip_mdd_ext__tcp_adjust_mss
    # no ip redirects
    if service_ipv6.config.oc_if_ip_mdd_ext__redirects:
        interface_cdb.ipv6.redirects = True
    elif service_ipv6.config.oc_if_ip_mdd_ext__redirects is False:
        interface_cdb.ipv6.redirects = False
    # no ip unreachables
    if service_ipv6.config.oc_if_ip_mdd_ext__unreachables:
        interface_cdb.ipv6.unreachables = True
    elif service_ipv6.config.oc_if_ip_mdd_ext__unreachables is False:
        interface_cdb.ipv6.unreachables = False


def xe_configure_vrrp_v3(self, interface_cdb: ncs.maagic.ListElement,
                              service_ip: ncs.maagic.Container,
                              address_family: str) -> None:
    """
    Configures ipv4 vrrp v3 with ipv4 support
    """
    for a in service_ip.addresses.address:
        if hasattr(a, 'vrrp'):
            if a.vrrp.vrrp_group:
                for v in a.vrrp.vrrp_group:
                    if not interface_cdb.vrrv3p_v3.vrrp.exists((v.virtual_router_id, address_family)):
                        interface_cdb.vrrv3p_v3.vrrp.create(v.virtual_router_id, address_family)
                    vrrp_group = interface_cdb.vrrv3p_v3.vrrp[v.virtual_router_id, address_family]
                    configure_vrrp(vrrp_group, v, False, address_family)

def xe_configure_vrrp_v2_legacy(self, interface_cdb: ncs.maagic.ListElement, service_ipv4: ncs.maagic.Container) -> None:
    """
    Configures ipv4 vrrp v2 legacy
    """
    # VRRP
    # check for an ipv6 address. if so uses vrrpv3 with vrrpv2 enabled, else below
    for a in service_ipv4.addresses.address:
        if hasattr(a, 'vrrp'):
            if a.vrrp.vrrp_group:
                for v in a.vrrp.vrrp_group:
                    if not interface_cdb.vrrp.exists(v.virtual_router_id):
                        interface_cdb.vrrp.create(v.virtual_router_id)
                    vrrp_group = interface_cdb.vrrp[v.virtual_router_id]
                    configure_vrrp(vrrp_group, v)

def configure_vrrp(vrrp_group, oc_vrrp_group, is_v2 = True, address_family = None):
    # accept_mode TODO
    # priority
    if oc_vrrp_group.config.priority:
        vrrp_group.priority = oc_vrrp_group.config.priority
    else:
        if vrrp_group.priority != None:
            vrrp_group.priority.delete()
    # preempt
    if oc_vrrp_group.config.preempt:
        if oc_vrrp_group.config.preempt_delay:
            vrrp_group.preempt.delay.minimum = oc_vrrp_group.config.preempt_delay
        else:
            vrrp_group.preempt.delay.minimum = 0
    else:
        if vrrp_group.preempt.delay.minimum != None:
            vrrp_group.preempt.delay.minimum.delete()
    # virtual address
    if oc_vrrp_group.config.virtual_address:
        for counter, address in enumerate(oc_vrrp_group.config.virtual_address):
            if is_v2:
                if counter == 0:
                    vrrp_group.ip.address = address
                # else:  TODO add secondaries
                #     vrrp_group.ip.secondary_address.create(address)
            else:
                if counter == 0:
                    address_1 = vrrp_group.address.primary_list.create(address)
                    if address_family == 'ipv6':
                        address_1.primary.create()
                # else:  TODO add secondaries
                #     vrrp_group.address.secondary_address.create(address)
    else:
        if vrrp_group.ip.address:
            vrrp_group.ip.address.delete()
    if oc_vrrp_group.config.advertisement_interval:  # <100-40950>  Advertisement interval in milliseconds
        if is_v2:
            vrrp_group.timers.advertise.seconds = oc_vrrp_group.config.advertisement_interval // 100  # oc-ip uses centiseconds
        else:
            msec = oc_vrrp_group.config.advertisement_interval * 10
            if 100 < msec < 40950:
                vrrp_group.timers.advertise.seconds = msec
            else:
                raise ValueError('XE VRRPv3 advertisement interval must be between 10 and 4095 centiseconds')
    else:
        if vrrp_group.timers.advertise.seconds != None:
            vrrp_group.timers.advertise.seconds.delete()
    # VRRP interface tracking TODO

def xe_configure_hsrp_v1(self, interface_cdb: ncs.maagic.ListElement, service_ipv4: ncs.maagic.Container) -> None:
    """
    Configures ipv4 hsrp
    """
    for a in service_ipv4.addresses.address:
        if hasattr(a, 'hsrp'):
            if a.hsrp.hsrp_group:
                for v in a.hsrp.hsrp_group:
                    if not interface_cdb.standby.standby_list.exists(v.group_number):
                        interface_cdb.standby.standby_list.create(v.group_number)
                    hsrp_group = interface_cdb.standby.standby_list[v.group_number]
                    # priority
                    if v.config.priority:
                        hsrp_group.priority = v.config.priority
                    # preempt
                    if v.config.preempt:
                        if not hsrp_group.preempt.exists():
                            hsrp_group.preempt.create()
                        if v.config.preempt_delay:
                            hsrp_group.preempt.delay.minimum = v.config.preempt_delay
                        else:
                            hsrp_group.preempt.delay.minimum = 0
                    # virtual address
                    if v.config.virtual_address:
                        if not hsrp_group.ip.exists():
                            hsrp_group.ip.create()
                        for counter, address in enumerate(v.config.virtual_address):
                            if counter == 0:
                                hsrp_group.ip.address = address
                            # else:  TODO add secondaries
                            #     hsrp_group.ip.secondary_address.create(address)
                    if v.config.timers:
                        hsrp_group.timers.hello_interval.seconds = v.config.timers.hello_interval
                        hsrp_group.timers.hold_time.seconds = v.config.timers.holdtime


def xe_configure_switched_vlan(self, nso_props,
                               interface_cdb: ncs.maagic.ListElement,
                               service_switched_vlan: ncs.maagic.Container) -> None:
    """
    Configures openconfig-vlan vlan-switched-top
    """

    if service_switched_vlan.config.interface_mode == 'TRUNK':
        if not interface_cdb.switchport.exists():
            interface_cdb.switchport.create()
        if len(nso_props.root.devices.device[nso_props.device_name].config.ios__switch.list) > 0:
            if 'c9k' in nso_props.root.devices.device[nso_props.device_name].config.ios__switch.list[1].provision:
                pass
            else:
                interface_cdb.switchport.trunk.encapsulation = 'dot1q'
        else:
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


def xe_interface_storm_control(interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement) -> None:
    # broadcast
    if interface_service.oc_eth__ethernet.storm_control.broadcast.level.config.suppression_type == "NONE":
        if interface_cdb.storm_control.broadcast.level_bps_pps.level.bps or interface_cdb.storm_control.broadcast.level_bps_pps.level.pps:
            interface_cdb.storm_control.broadcast.delete()
    elif interface_service.oc_eth__ethernet.storm_control.broadcast.level.config.suppression_type != "NONE":
        if interface_service.oc_eth__ethernet.storm_control.broadcast.level.config.suppression_type == "BPS":
            interface_cdb.storm_control.broadcast.level_bps_pps.level.bps = interface_service.oc_eth__ethernet.storm_control.broadcast.level.config.bps
        elif interface_service.oc_eth__ethernet.storm_control.broadcast.level.config.suppression_type == "PPS":
            interface_cdb.storm_control.broadcast.level_bps_pps.level.pps = interface_service.oc_eth__ethernet.storm_control.broadcast.level.config.pps
      # unicast
    if interface_service.oc_eth__ethernet.storm_control.unicast.level.config.suppression_type == "NONE":
        if interface_cdb.storm_control.unicast.level_bps_pps.level.bps or interface_cdb.storm_control.unicast.level_bps_pps.level.pps:
            interface_cdb.storm_control.unicast.delete()
    elif interface_service.oc_eth__ethernet.storm_control.unicast.level.config.suppression_type != "NONE":
        if interface_service.oc_eth__ethernet.storm_control.unicast.level.config.suppression_type == "BPS":
            interface_cdb.storm_control.unicast.level_bps_pps.level.bps = interface_service.oc_eth__ethernet.storm_control.unicast.level.config.bps
        elif interface_service.oc_eth__ethernet.storm_control.unicast.level.config.suppression_type == "PPS":
            interface_cdb.storm_control.unicast.level_bps_pps.level.pps = interface_service.oc_eth__ethernet.storm_control.unicast.level.config.pps