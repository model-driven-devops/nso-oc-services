# -*- mode: python; python-indent: 4 -*-
import ipaddress
import re

import ncs
from translation.common import get_interface_type_and_number

speeds_oc_to_xr = {
    'SPEED_100MB': '100',
    'SPEED_1GB': '1000',
    'SPEED_10GB': '10000',
    'SPEED_25GB': '25000',
    'SPEED_40GB': '40000',
    'SPEED_100GB': '100000'
}


def xr_interfaces_program_service(self) -> None:
    """
    Program service for xr NED features too complex for XML template.
    """
    xr_update_vlan_db(self)
    xr_process_interfaces(self)


def xr_update_vlan_db(self) -> None:
    """
    Ensure vlan is available for incoming configuration
    """

    # Get VLANs from device VLAN DB
    vlans_device_db = list()
    for v in self.root.devices.device[self.device_name].config.cisco_ios_xr__vlan.vlan_list:
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
        self.root.devices.device[self.device_name].config.cisco_ios_xr__vlan.vlan_list.create(v)
        vlan = self.root.devices.device[self.device_name].config.cisco_ios_xr__vlan.vlan_list[v]


def check_for_ipv6(s):
    """
    Is IPv6 being used?
    """
    for interface in s.service.oc_if__interfaces.interface:
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


def xr_process_interfaces(self) -> None:
    """
    Programs device interfaces as defined in model
    """
    routing_ipv6 = check_for_ipv6(self)
    if routing_ipv6:
        self.root.devices.device[self.device_name].config.cisco_ios_xr__ipv6.unicast_routing.create()
    for interface in self.service.oc_if__interfaces.interface:
        # Layer 3 VLAN interfaces
        if interface.config.type == 'ianaift:l3ipvlan':
            if not self.root.devices.device[self.device_name].config.cisco_ios_xr__interface.Vlan.exists(
                    interface.routed_vlan.config.vlan):
                self.root.devices.device[self.device_name].config.cisco_ios_xr__interface.Vlan.create(
                    interface.routed_vlan.config.vlan)

            vlan = self.root.devices.device[self.device_name].config.cisco_ios_xr__interface.Vlan[
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
            xr_configure_ipv4(self, vlan, interface.routed_vlan.ipv4)
            xr_configure_hsrp_v1(self, vlan, interface.routed_vlan.ipv4, interface)
            xr_configure_ipv6(self, vlan, interface.routed_vlan.ipv6)
            if routing_ipv6:
                xr_configure_vrrp_v3(self, vlan, interface.routed_vlan.ipv4, interface, 'ipv4')
                xr_configure_vrrp_v3(self, vlan, interface.routed_vlan.ipv6, interface, 'ipv6')
            else:
                xr_configure_vrrp_v2_legacy(self, vlan, interface.routed_vlan.ipv4, interface)

        # Layer 2 interfaces
        elif interface.config.type == 'ianaift:l2vlan' or (
                interface.config.type == 'ianaift:ethernetCsmacd' and interface.ethernet.config.aggregate_id):
            interface_type, interface_number = get_interface_type_and_number(interface.config.name)
            class_attribute = getattr(self.root.devices.device[self.device_name].config.cisco_ios_xr__interface,
                                      interface_type)
            l2_interface = class_attribute[interface_number]
            xr_interface_config(interface, l2_interface)
            xr_interface_hold_time(interface, l2_interface)
            xr_interface_ethernet(self, interface, l2_interface)

        # Bundle-Ether
        elif interface.config.type == 'ianaift:ieee8023adLag':
            interface_type, interface_number = get_interface_type_and_number(interface.config.name)
            # XR expects Bundle-Ether, regex returns Port-channel
            if interface_type == 'Port_channel':
                interface_type = 'Bundle_Ether'
            class_attribute = getattr(self.root.devices.device[self.device_name].config.cisco_ios_xr__interface,
                                      interface_type)
            if not class_attribute.exists(interface_number):
                class_attribute.create(interface_number)
            bundle_ether = class_attribute[interface_number]
            xr_interface_config(interface, bundle_ether)
            xr_interface_hold_time(interface, bundle_ether)
            if len(interface.subinterfaces.subinterface) == 0:
                xr_interface_aggregation(self, interface, bundle_ether, routing_ipv6, interface_number)
            else:
                for subinterface_service in interface.subinterfaces.subinterface:
                    if subinterface_service.index != 0:
                        class_attribute_sub_if = self.root.devices.device[
                            self.device_name].config.cisco_ios_xr__interface.Bundle_Ether_subinterface.Bundle_Ether
                        if not class_attribute_sub_if.exists(f'{interface_number}.{subinterface_service.index}'):
                            class_attribute_sub_if.create(f'{interface_number}.{subinterface_service.index}')
                        subinterface_cdb = class_attribute_sub_if[f'{interface_number}.{subinterface_service.index}']
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
                        if subinterface_cdb.encapsulation.dot1q.vlan_id.exists():
                            subinterface_cdb.encapsulation.dot1q.vlan_id.delete()
                            subinterface_cdb.encapsulation.dot1q.vlan_id.create(
                                subinterface_service.vlan.config.vlan_id)
                        else:
                            subinterface_cdb.encapsulation.dot1q.vlan_id.create(
                                subinterface_service.vlan.config.vlan_id)
                        xr_configure_ipv4(self, subinterface_cdb, subinterface_service.ipv4)
                        # HSRP v1
                        xr_configure_hsrp_v1(self, subinterface_cdb, subinterface_service.ipv4, interface)
                        xr_configure_ipv6(self, subinterface_cdb, subinterface_service.ipv6)
                        if routing_ipv6:
                            xr_configure_vrrp_v3(self, subinterface_cdb, subinterface_service.ipv4, interface, 'ipv4')
                            xr_configure_vrrp_v3(self, subinterface_cdb, subinterface_service.ipv6, interface, 'ipv6')
                        else:
                            xr_configure_vrrp_v2_legacy(self, subinterface_cdb, subinterface_service.ipv4, interface)
                    else:  # IPv4 for main interface
                        xr_interface_aggregation(self, interface, bundle_ether, routing_ipv6, interface_number)

        # Physical and Sub-interfaces
        elif interface.config.type == 'ianaift:ethernetCsmacd':
            interface_type, interface_number = get_interface_type_and_number(interface.config.name)
            class_attribute = getattr(self.root.devices.device[self.device_name].config.cisco_ios_xr__interface,
                                      interface_type)
            physical_interface = class_attribute[interface_number]
            xr_interface_config(interface, physical_interface)
            xr_interface_hold_time(interface, physical_interface)
            if interface.ethernet.switched_vlan.config.interface_mode:
                raise ValueError('NSO XR CLI NED cisco-iosxr-cli-7.41 does not support l2vlan')
            xr_interface_ethernet(self, interface, physical_interface)
            for subinterface_service in interface.subinterfaces.subinterface:
                if subinterface_service.index != 0:
                    attribute1 = getattr(self.root.devices.device[self.device_name].config.cisco_ios_xr__interface,
                                         f'{interface_type}_subinterface')
                    class_attribute_sub_if = getattr(attribute1, interface_type)
                    if not class_attribute_sub_if.exists(f'{interface_number}.{subinterface_service.index}'):
                        class_attribute_sub_if.create(f'{interface_number}.{subinterface_service.index}')
                    subinterface_cdb = class_attribute_sub_if[f'{interface_number}.{subinterface_service.index}']

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
                    if subinterface_cdb.encapsulation.dot1q.vlan_id.exists():
                        subinterface_cdb.encapsulation.dot1q.vlan_id.delete()
                        subinterface_cdb.encapsulation.dot1q.vlan_id.create(subinterface_service.vlan.config.vlan_id)
                    else:
                        subinterface_cdb.encapsulation.dot1q.vlan_id.create(subinterface_service.vlan.config.vlan_id)
                    xr_configure_ipv4(self, subinterface_cdb, subinterface_service.ipv4)
                    xr_configure_hsrp_v1(self, subinterface_cdb, subinterface_service.ipv4, interface)
                    xr_configure_ipv6(self, subinterface_cdb, subinterface_service.ipv6)
                    if routing_ipv6:
                        xr_configure_vrrp_v3(self, subinterface_cdb, subinterface_service.ipv4, interface, 'ipv4')
                        xr_configure_vrrp_v3(self, subinterface_cdb, subinterface_service.ipv6, interface, 'ipv6')
                    else:
                        xr_configure_vrrp_v2_legacy(self, subinterface_cdb, subinterface_service.ipv4, interface)
                else:  # IPv4 for main interface
                    # Remove switchport
                    if physical_interface.switchport:
                        physical_interface.switchport.delete()
                    xr_configure_ipv4(self, physical_interface, subinterface_service.ipv4)
                    xr_configure_hsrp_v1(self, physical_interface, subinterface_service.ipv4, interface)
                    xr_configure_ipv6(self, physical_interface, subinterface_service.ipv6)
                    if routing_ipv6:
                        xr_configure_vrrp_v3(self, physical_interface, subinterface_service.ipv4, interface, 'ipv4')
                        xr_configure_vrrp_v3(self, physical_interface, subinterface_service.ipv6, interface, 'ipv6')
                    else:
                        xr_configure_vrrp_v2_legacy(self, physical_interface, subinterface_service.ipv4, interface)

        # Loopback interfaces
        elif interface.config.type == 'ianaift:softwareLoopback':
            interface_type, interface_number = get_interface_type_and_number(interface.config.name)
            if not self.root.devices.device[self.device_name].config.cisco_ios_xr__interface.Loopback.exists(
                    interface_number):
                self.root.devices.device[self.device_name].config.cisco_ios_xr__interface.Loopback.create(
                    interface_number)
            loopback = self.root.devices.device[self.device_name].config.cisco_ios_xr__interface.Loopback[
                interface_number]
            xr_interface_config(interface, loopback)
            xr_configure_ipv4(self, loopback, interface.subinterfaces.subinterface[0].ipv4)
            xr_configure_ipv6(self, loopback, interface.subinterfaces.subinterface[0].ipv6)

        # VASI interfaces
        elif interface.config.type == 'iftext:vasi':
            raise ValueError('NSO XR CLI NED cisco-iosxr-cli-7.41 does not support VASI interfaces')

        # GRE Tunnel interface
        elif interface.config.type == 'ianaift:tunnel':
            interface_type, interface_number = get_interface_type_and_number(interface.config.name)
            # XR expects tunnel_ip, regex returns Tunnel
            if interface_type == 'Tunnel':
                interface_type = 'tunnel_ip'
            class_attribute = getattr(self.root.devices.device[self.device_name].config.cisco_ios_xr__interface,
                                      interface_type)
            if not class_attribute.exists(interface_number):
                class_attribute.create(interface_number)
            tunnel_interface = class_attribute[interface_number]
            xr_interface_config(interface, tunnel_interface)
            xr_configure_tunnel_interface(interface, tunnel_interface)
            xr_configure_ipv4(self, tunnel_interface, interface.oc_tun__tunnel.ipv4)
            xr_configure_ipv6(self, tunnel_interface, interface.oc_tun__tunnel.ipv6)
        else:
            raise ValueError(
                f'Interface type {interface.config.type} not supported by this NSO_OC_Services implementation. Please file an issue at https://github.com/model-driven-devops/nso-oc-services')


def xr_configure_tunnel_interface(interface_service: ncs.maagic.ListElement,
                                  interface_cdb: ncs.maagic.ListElement) -> None:
    if interface_service.oc_tun__tunnel.config.src:
        interface_cdb.tunnel.source = interface_service.oc_tun__tunnel.config.src
    if interface_service.oc_tun__tunnel.config.dst:
        interface_cdb.tunnel.destination = interface_service.oc_tun__tunnel.config.dst
    # Mode GRE IPv4
    interface_cdb.tunnel.mode.gre = 'ipv4'
    if interface_service.oc_tun__tunnel.config.gre_key:
        raise ValueError('NSO XR CLI NED cisco-iosxr-cli-7.41 does not support GRE Tunnel Keys')
    if interface_service.oc_tun__tunnel.config.oc_if_tun_ext__tunnel_path_mtu_discovery:
        raise ValueError('NSO XR CLI NED cisco-iosxr-cli-7.41 does not support GRE Tunnel path mtu discovery')
    if interface_service.oc_tun__tunnel.config.oc_if_tun_ext__keepalives.oc_if_tun_ext__period and interface_service.oc_tun__tunnel.config.oc_if_tun_ext__keepalives.oc_if_tun_ext__retries:
        interface_cdb.keepalive.values.interval = interface_service.oc_tun__tunnel.config.oc_if_tun_ext__keepalives.oc_if_tun_ext__period
        interface_cdb.keepalive.values.retry = interface_service.oc_tun__tunnel.config.oc_if_tun_ext__keepalives.oc_if_tun_ext__retries
    if interface_service.oc_tun__tunnel.config.ttl:
        raise ValueError('NSO XR CLI NED cisco-iosxr-cli-7.41 does not support Tunnel TTL')


def xr_get_subinterfaces(self) -> list:
    """
    Returns a list of existing subinterfaces
    """
    interfaces = list()
    device_config = self.root.devices.device[self.device_name].config
    for a in dir(device_config.cisco_ios_xr__interface):
        if not a.startswith('__'):
            class_method = getattr(device_config.cisco_ios_xr__interface, a)
            for i in class_method:
                try:
                    if '.' in str(i.name):
                        interfaces.append(str(i) + str(i.name))
                except:
                    pass
    return interfaces


def xr_interface_ethernet(s, interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement) -> None:
    # auto-negotiate
    # This doesn't work on CML 2.4 IOS XRv 9000
    if interface_service.ethernet.config.auto_negotiate:
        interface_cdb.negotiation.auto.create()
    elif interface_service.ethernet.config.auto_negotiate is False:
        if interface_cdb.negotiation.auto.exists():
            interface_cdb.negotiation.auto.delete()
        # port-speed - may need to be set before duplex is configured
        # This doesn't work on CML 2.4 IOS XRv 9000
        if interface_service.ethernet.config.port_speed:
            interface_cdb.speed = speeds_oc_to_xr.get(interface_service.ethernet.config.port_speed)
        # duplex-mode
        # This doesn't work on CML 2.4 IOS XRv 9000
        if interface_service.ethernet.config.duplex_mode:
            interface_cdb.duplex = str(interface_service.ethernet.config.duplex_mode).lower()
    # port-speed
    # This doesn't work on CML 2.4 IOS XRv 9000
    if interface_service.ethernet.config.port_speed:
        interface_cdb.speed = speeds_oc_to_xr.get(interface_service.ethernet.config.port_speed)
    # enable-flow-control
    # This doesn't work on CML 2.4 IOS XRv 9000
    if interface_service.ethernet.config.enable_flow_control is True:
        interface_cdb.flow_control = 'bidirectional'
    elif interface_service.ethernet.config.enable_flow_control is False:
        interface_cdb.flow_control = None
    # mac-address
    if interface_service.ethernet.config.mac_address:
        xr_mac = f'{interface_service.ethernet.config.mac_address[0:2]}{interface_service.ethernet.config.mac_address[3:5]}.{interface_service.ethernet.config.mac_address[6:8]}{interface_service.ethernet.config.mac_address[9:11]}.{interface_service.ethernet.config.mac_address[12:14]}{interface_service.ethernet.config.mac_address[15:17]}'
        interface_cdb.mac_address = xr_mac
    # poe
    if interface_service.ethernet.switched_vlan.config.interface_mode:
        raise ValueError('NSO XR CLI NED cisco-iosxr-cli-7.41 does not support poe')

    # switched-vlan interface-mode
    if interface_service.ethernet.switched_vlan.config.interface_mode:
        xr_configure_switched_vlan(s, interface_cdb, interface_service.ethernet.switched_vlan)
    else:
        if interface_cdb.switchport:
            interface_cdb.switchport.delete()
    if interface_service.ethernet.config.aggregate_id:
        interface_cdb.channel_protocol.number = xr_get_bundle_number(
            interface_service.ethernet.config.aggregate_id)
        interface_cdb.channel_protocol.mode = 'active'


def xr_interface_aggregation(s, interface_service: ncs.maagic.ListElement,
                             interface_cdb: ncs.maagic.ListElement, ipv6: bool, interface_number) -> None:
    if interface_service.aggregation.config.min_links:
        interface_cdb.bundle.minimum_active.links = int(interface_service.aggregation.config.min_links)

    if interface_service.aggregation.switched_vlan.config.interface_mode:
        xr_configure_switched_vlan(s, interface_cdb, interface_service.aggregation.switched_vlan)
    else:
        if interface_cdb.switchport:
            interface_cdb.switchport.delete()
    if interface_service.aggregation.ipv4.addresses.address:
        xr_configure_ipv4(s, interface_cdb, interface_service.aggregation.ipv4)
        xr_configure_hsrp_v1(s, interface_cdb, interface_service.aggregation.ipv4, interface_service)
        xr_configure_ipv6(s, interface_cdb, interface_service.aggregation.ipv6)
        if ipv6:
            xr_configure_vrrp_v3(s, interface_cdb, interface_service.aggregation.ipv4, interface_service, 'ipv4')
            xr_configure_vrrp_v3(s, interface_cdb, interface_service.aggregation.ipv6, interface_service, 'ipv6')
        else:
            xr_configure_vrrp_v2_legacy(s, interface_cdb, interface_service.aggregation.ipv4, interface_service)


def xr_configure_ipv4(s, interface_cdb: ncs.maagic.ListElement, service_ipv4: ncs.maagic.Container) -> None:
    """
    Configures openconfig-if-ip ipv4-top
    """
    # Get current cdb addresses
    ips_and_masks_cdb = list()
    for x in interface_cdb.ipv4.address_secondary_list.address:
        ips_and_masks_cdb.append((x.address, x.mask))

    # Create service config address mask list
    ips_and_masks = list()
    if service_ipv4.addresses.address:
        if interface_cdb.ipv4.address_dhcp.address.dhcp.exists():
            interface_cdb.ipv4.address_dhcp.address.dhcp.delete()
        for a in service_ipv4.addresses.address:
            ip = ipaddress.ip_network(f'10.0.0.0/{a.config.prefix_length}')
            ips_and_masks.append((a.config.ip, str(ip.netmask)))

        # Remove unrequested IPs from CDB
        ips_to_remove = list()
        for ips in ips_and_masks_cdb:
            if ips not in ips_and_masks[1:]:
                ips_to_remove.append(ips)
        for ips in ips_to_remove:
            del interface_cdb.ipv4.address_secondary_list.address[ips]

        # Update/Create needed IP addresses in CDB
        for counter, ip_mask in enumerate(ips_and_masks):
            if counter == 0:
                interface_cdb.ipv4.address.ip = ip_mask[0]
                interface_cdb.ipv4.address.mask = ip_mask[1]
            # elif counter > 0: TODO
            #     if not interface_cdb.ip.address.secondary.exists(ip_mask):
            #         interface_cdb.ip.address.secondary.create(ip_mask)
    else:
        if service_ipv4.config.dhcp_client:
            interface_cdb.ipv4.address_dhcp.address.dhcp.create()
    if service_ipv4.config.dhcp_client is False:
        if interface_cdb.ipv4.address_dhcp.address.dhcp.exists():
            interface_cdb.ipv4.address_dhcp.address.dhcp.delete()
    # ip mtu
    if service_ipv4.config.mtu:
        interface_cdb.ipv4.mtu = service_ipv4.config.mtu
    # adjust TCP MSS - CML Testing issues
    # if service_ipv4.config.oc_if_ip_mdd_ext__tcp_adjust_mss:
    #     interface_cdb.ipv4.tcp_mss_adjust = service_ipv4.config.oc_if_ip_mdd_ext__tcp_adjust_mss
    # no ip redirects
    if service_ipv4.config.oc_if_ip_mdd_ext__redirects:
        interface_cdb.ipv4.redirects.create()
    elif service_ipv4.config.oc_if_ip_mdd_ext__redirects is False:
        if interface_cdb.ipv4.redirects:
            interface_cdb.ipv4.redirects.delete()
    # no ip unreachables
    if service_ipv4.config.oc_if_ip_mdd_ext__unreachables:
        if interface_cdb.ipv4.unreachables.disable:
            interface_cdb.ipv4.unreachables.disable.delete()
    elif service_ipv4.config.oc_if_ip_mdd_ext__unreachables is False:
        interface_cdb.ipv4.unreachables.disable.create()
    # proxy-arp
    if service_ipv4.proxy_arp.config.mode == 'DISABLE':
        if interface_cdb.proxy_arp:
            interface_cdb.proxy_arp.delete()
    if service_ipv4.proxy_arp.config.mode == 'REMOTE_ONLY':
        interface_cdb.proxy_arp.create()
    # reply-mask
    if service_ipv4.config.oc_if_ip_mdd_ext__mask_reply:
        interface_cdb.ipv4.mask_reply.create()
    elif service_ipv4.config.oc_if_ip_mdd_ext__mask_reply is False:
        if interface_cdb.ipv4.mask_reply.exists():
            interface_cdb.ipv4.mask_reply.delete()
    # NAT interface
    if service_ipv4.config.oc_if_ip_mdd_ext__nat.nat_choice == 'inside':
        raise ValueError('NSO XR CLI NED cisco-iosxr-cli-7.41 does not support Inside NAT')
    elif service_ipv4.config.oc_if_ip_mdd_ext__nat.nat_choice == 'outside':
        raise ValueError('NSO XR CLI NED cisco-iosxr-cli-7.41 does not support Outside NAT')
    elif service_ipv4.config.oc_if_ip_mdd_ext__nat.nat_choice == 'disabled':
        raise ValueError('NSO XR CLI NED cisco-iosxr-cli-7.41 does not support NAT')


def xr_configure_ipv6(s, interface_cdb: ncs.maagic.ListElement, service_ipv6: ncs.maagic.Container) -> None:
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

    if service_ipv6.config.dhcp_client is False:
        if interface_cdb.ipv6.address.dhcp.exists():
            interface_cdb.ipv6.address.dhcp.delete()
    # ip mtu
    if service_ipv6.config.mtu:
        interface_cdb.ipv6.mtu = service_ipv6.config.mtu
    # adjust TCP MSS
    if service_ipv6.config.oc_if_ip_mdd_ext__tcp_adjust_mss:
        interface_cdb.ipv6.tcp_mss_adjust = service_ipv6.config.oc_if_ip_mdd_ext__tcp_adjust_mss
    # no ip redirects TODO
    if service_ipv6.config.oc_if_ip_mdd_ext__redirects:
        raise ValueError('NSO XR CLI NED cisco-iosxr-cli-7.41 does not support no ipv6 redirects')
    # no ip unreachables
    if service_ipv6.config.oc_if_ip_mdd_ext__unreachables:
        interface_cdb.ipv6.unreachables.disable.create()
    elif service_ipv6.config.oc_if_ip_mdd_ext__unreachables is False:
        if interface_cdb.ipv6.unreachables.disable:
            interface_cdb.ipv6.unreachables.disable.delete()


def xr_configure_vrrp_v3(s, interface_cdb: ncs.maagic.ListElement,
                         service_ip: ncs.maagic.Container,
                         interface_service: ncs.maagic.ListElement,
                         address_family: str) -> None:
    """
    Configures ipv4 vrrp v3 with ipv4 support
    """
    for a in service_ip.addresses.address:
        if hasattr(a, 'vrrp'):
            if a.vrrp.vrrp_group:
                for v in a.vrrp.vrrp_group:
                    vrrpv3_interface = s.root.devices.device[s.device_name].config.cisco_ios_xr__router.vrrp.interface
                    if not vrrpv3_interface.exists(f'{interface_service.name}'):
                        vrrpv3_interface.create(f'{interface_service.name}')
                        if address_family == 'ipv4':
                            vrrpv3_interface[f'{interface_service.name}'].address_family.ipv4.vrrp.create(
                                v.virtual_router_id)
                        else:
                            vrrpv3_interface[f'{interface_service.name}'].address_family.ipv6.vrrp.create(
                                v.virtual_router_id)
                    else:
                        if address_family == 'ipv4':
                            vrrpv3_interface[f'{interface_service.name}'].address_family.ipv4.vrrp.create(
                                v.virtual_router_id)
                        else:
                            vrrpv3_interface[f'{interface_service.name}'].address_family.ipv6.vrrp.create(
                                v.virtual_router_id)
                    if address_family == 'ipv4':
                        vrrpv3_group = vrrpv3_interface[f'{interface_service.name}'].address_family.ipv4.vrrp[
                            v.virtual_router_id]
                    else:
                        vrrpv3_group = vrrpv3_interface[f'{interface_service.name}'].address_family.ipv6.vrrp[
                            v.virtual_router_id]
                    # priority
                    if v.config.priority:
                        vrrpv3_group.priority = v.config.priority
                    # preempt
                    if v.config.preempt:
                        if v.config.preempt_delay:
                            vrrpv3_group.preempt.delay = v.config.preempt_delay
                        else:
                            vrrpv3_group.preempt.delay = 0
                    # virtual address
                    if v.config.virtual_address:
                        for counter, address in enumerate(v.config.virtual_address):
                            if counter == 0:
                                vrrpv3_group.address.create(address)
                    if v.config.advertisement_interval:
                        vrrpv3_group.timer.time_value = v.config.advertisement_interval // 100  # oc-ip uses centiseconds
                    # VRRP interface tracking TODO


def xr_configure_vrrp_v2_legacy(s, interface_cdb: ncs.maagic.ListElement, service_ipv4: ncs.maagic.Container,
                                interface_service: ncs.maagic.ListElement) -> None:
    """
    Configures ipv4 vrrp v2 legacy
    """
    # VRRP
    # check for an ipv6 address. if so uses vrrpv3 with vrrpv2 enabled, else below
    for a in service_ipv4.addresses.address:
        if hasattr(a, 'vrrp'):
            if a.vrrp.vrrp_group:
                for v in a.vrrp.vrrp_group:
                    vrrpv2_interface = s.root.devices.device[s.device_name].config.cisco_ios_xr__router.vrrp.interface
                    if not vrrpv2_interface.exists(f'{interface_service.name}'):
                        vrrpv2_interface.create(f'{interface_service.name}')
                        vrrpv2_interface[f'{interface_service.name}'].address_family.ipv4.vrrp.create(
                            v.virtual_router_id)
                    else:
                        vrrpv2_interface[f'{interface_service.name}'].address_family.ipv4.vrrp.create(
                            v.virtual_router_id)
                    vrrpv2_group = vrrpv2_interface[f'{interface_service.name}'].address_family.ipv4.vrrp[
                        v.virtual_router_id]
                    # priority
                    if v.config.priority:
                        vrrpv2_group.priority = v.config.priority
                    # preempt
                    if v.config.preempt:
                        if v.config.preempt_delay:
                            vrrpv2_group.preempt.delay = v.config.preempt_delay
                        else:
                            vrrpv2_group.preempt.delay = 0
                    # virtual address
                    if v.config.virtual_address:
                        for counter, address in enumerate(v.config.virtual_address):
                            if counter == 0:
                                vrrpv2_group.address.create(address)
                    if v.config.advertisement_interval:
                        vrrpv2_group.timer.time_value = v.config.advertisement_interval // 100  # oc-ip uses centiseconds
                    # VRRP interface tracking TODO


def xr_configure_hsrp_v1(s, interface_cdb: ncs.maagic.ListElement, service_ipv4: ncs.maagic.Container,
                         interface_service: ncs.maagic.ListElement) -> None:
    """
    Configures ipv4 hsrp
    """
    for a in service_ipv4.addresses.address:
        if hasattr(a, 'hsrp'):
            if a.hsrp.hsrp_group:
                for v in a.hsrp.hsrp_group:
                    hsrpv1_interface = s.root.devices.device[s.device_name].config.cisco_ios_xr__router.hsrp.interface
                    if not hsrpv1_interface.exists(f'{interface_service.name}'):
                        hsrpv1_interface.create(f'{interface_service.name}')
                        hsrpv1_interface[
                            f'{interface_service.name}'].address_family.ipv4.hsrp_version1_list.hsrp.create(
                            v.group_number)
                    else:
                        hsrpv1_interface[
                            f'{interface_service.name}'].address_family.ipv4.hsrp_version1_list.hsrp.create(
                            v.group_number)
                    hsrpv1_group = \
                    hsrpv1_interface[f'{interface_service.name}'].address_family.ipv4.hsrp_version1_list.hsrp[
                        v.group_number]
                    # priority
                    if v.config.priority:
                        hsrpv1_group.priority = v.config.priority
                    # preempt
                    if v.config.preempt:
                        if not hsrpv1_group.preempt.exists():
                            hsrpv1_group.preempt.create()
                        if v.config.preempt_delay:
                            hsrpv1_group.preempt.delay = v.config.preempt_delay
                        else:
                            hsrpv1_group.preempt.delay = 0
                    # virtual address
                    if v.config.virtual_address:
                        for counter, address in enumerate(v.config.virtual_address):
                            if counter == 0:
                                hsrpv1_group.address = address
                            else:
                                hsrpv1_group.address_secondary_list.address.create(address)
                    if v.config.timers:
                        hsrpv1_group.timers.hello_seconds = v.config.timers.hello_interval
                        hsrpv1_group.timers.hold_seconds = v.config.timers.holdtime


def xr_configure_switched_vlan(self,
                               interface_cdb: ncs.maagic.ListElement,
                               service_switched_vlan: ncs.maagic.Container) -> None:
    """
    Configures openconfig-vlan vlan-switched-top
    """

    if service_switched_vlan.config.interface_mode == 'TRUNK':
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
        if not interface_cdb.switchport.mode.access.exists():
            interface_cdb.switchport.mode.access.create()
        if service_switched_vlan.config.access_vlan:
            interface_cdb.switchport.access.vlan = int(
                service_switched_vlan.config.access_vlan)


def xr_interface_config(interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement) -> None:
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
    # loopback-mode  TODO
    if interface_service.config.loopback_mode:
        pass
    # mtu
    if interface_service.config.mtu:
        interface_cdb.mtu = interface_service.config.mtu


def xr_interface_hold_time(interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement) -> None:
    if interface_service.hold_time.config.down:
        interface_cdb.carrier_delay.down = int(interface_service.hold_time.config.down)
    if interface_service.hold_time.config.up:
        interface_cdb.carrier_delay.up = int(interface_service.hold_time.config.up)


def xr_get_bundle_number(interface: str) -> int:
    bundle = re.search(r'\d+', interface)
    return int(bundle.group(0))