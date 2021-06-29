# -*- mode: python; python-indent: 4 -*-
import ipaddress
import re
from typing import Tuple

import ncs
import _ncs
from ncs.application import Service


class ServiceCallbacks(Service):
    @Service.create
    def cb_create(self, tctx: _ncs.TransCtxRef, root: ncs.maagic.Root, service: ncs.maagic.ListElement, proplist: list):
        """
        This is the main create/modify service method.
        Note any values needed by the service template must be added as keys to 'initial_vars'.
        The appropriate OS transform_vars will add the appropriate values to the keys.
        """
        self.log.info('Service create(service=', service._path, ')')

        self.service = service
        self.root = root
        self.proplist = proplist

        initial_vars = dict()

        # Each NED type with have a x_transform_vars here
        self.xe_transform_vars()
        self.log.info(self.proplist)
        final_vars = self.update_vars(initial_vars, self.proplist)
        vars_template = ncs.template.Variables()
        for k in final_vars:
            vars_template.add(k, final_vars[k])
        template = ncs.template.Template(service)
        template.apply('oc-interfaces-nso-template', vars_template)
        # Each NED type may have a x_program_service here
        self.xe_program_service()

    def xe_program_service(self):
        """
        Program service for xe NED features too complex for XML template.
        """
        self.xe_reconcile_vlan_db()
        self.xe_reconcile_vlan_interfaces()
        self.xe_reconcile_port_channel_interfaces()
        self.xe_reconcile_sub_interfaces()
        self.xe_process_interfaces()

    def xe_process_interfaces(self):
        """
        Programs device interfaces as defined in model
        """
        for i in self.service.openconfig_interfaces.interfaces.interface:
            # Layer 3 VLAN interfaces
            if i.config.type == 'ianaift:l3ipvlan':
                if not self.root.devices.device[self.service.name].config.ios__interface.Vlan.exists(
                        i.routed_vlan.config.vlan):
                    self.root.devices.device[self.service.name].config.ios__interface.Vlan.create(
                        i.routed_vlan.config.vlan)

                vlan = self.root.devices.device[self.service.name].config.ios__interface.Vlan[
                    i.routed_vlan.config.vlan]
                if i.config.description:
                    vlan.description = i.config.description
                if i.config.enabled:
                    if vlan.shutdown.exists():
                        vlan.shutdown.delete()
                else:
                    if not vlan.shutdown.exists():
                        vlan.shutdown.create()
                if i.config.mtu:
                    vlan.mtu = i.config.mtu
                self.xe_configure_ipv4(vlan, i.routed_vlan.ipv4)

            # Layer 2 interfaces
            if i.config.type == 'ianaift:l2vlan' or (
                    i.config.type == 'ianaift:ethernetCsmacd' and i.ethernet.config.aggregate_id):
                interface_type, interface_number = self.xe_get_interface_type_and_number(i.config.name)
                class_attribute = getattr(self.root.devices.device[self.service.name].config.ios__interface,
                                          interface_type)
                l2_interface = class_attribute[interface_number]
                self.xe_interface_config(i, l2_interface)
                self.xe_interface_hold_time(i, l2_interface)
                self.xe_interface_ethernet(i, l2_interface)

            # Port channels
            if i.config.type == 'ianaift:ieee8023adLag':
                port_channel_number = self.xe_get_port_channel_number(i.name)
                if not self.root.devices.device[self.service.name].config.ios__interface.Port_channel.exists(
                        port_channel_number):
                    self.root.devices.device[self.service.name].config.ios__interface.Port_channel.create(
                        port_channel_number)
                port_channel = self.root.devices.device[self.service.name].config.ios__interface.Port_channel[
                    port_channel_number]
                self.xe_interface_config(i, port_channel)
                self.xe_interface_hold_time(i, port_channel)
                self.xe_interface_aggregation(i, port_channel)

            # Physical ethernet
            if i.config.type == 'ianaift:ethernetCsmacd' and i.config.ipv4:
                interface_type, interface_number = self.xe_get_interface_type_and_number(i.config.name)
                class_attribute = getattr(self.root.devices.device[self.service.name].config.ios__interface,
                                          interface_type)
                l3_physical_interface_cdb = class_attribute[interface_number]
                self.xe_interface_config(i, l3_physical_interface_cdb)
                self.xe_interface_hold_time(i, l3_physical_interface_cdb)
                self.xe_interface_ethernet(i, l3_physical_interface_cdb)
                self.xe_configure_ipv4(l3_physical_interface_cdb, i.config.ipv4)

            # Sub-interfaces
            if i.config.type == 'ianaift:ethernetCsmacd' and i.subinterfaces.subinterface:
                interface_type, interface_number = self.xe_get_interface_type_and_number(i.config.name)
                class_attribute = getattr(self.root.devices.device[self.service.name].config.ios__interface,
                                          interface_type)
                physical_interface = class_attribute[interface_number]
                self.xe_interface_config(i, physical_interface)
                self.xe_interface_hold_time(i, physical_interface)
                self.xe_interface_ethernet(i, physical_interface)
                for subinterface_service in i.subinterfaces.subinterface:
                    self.log.info(f'subinterface is: {interface_type}  {interface_number}.{subinterface_service.index}')
                    if not class_attribute.exists(f'{interface_number}.{subinterface_service.index}'):
                        class_attribute.create(f'{interface_number}.{subinterface_service.index}')
                    subinterface_cdb = class_attribute[f'{interface_number}.{subinterface_service.index}']
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
                    self.xe_configure_ipv4(subinterface_cdb, subinterface_service.ipv4)

    def xe_get_subinterfaces(self) -> list:
        """
        Returns a list of existing subinterfaces
        """
        interfaces = list()
        device_config = self.root.devices.device[self.service.name].config
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

    def xe_interface_ethernet(self, interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement):
        # auto-negotiate
        if interface_service.ethernet.config.auto_negotiate:
            interface_cdb.negotiation.auto = interface_service.ethernet.config.auto_negotiate
        elif interface_service.ethernet.config.auto_negotiate is False:
            interface_cdb.negotiation.auto = interface_service.ethernet.config.auto_negotiate
            # duplex-mode
            if interface_service.ethernet.config.duplex_mode:
                interface_cdb.duplex = interface_service.config.description.lower()
        # port-speed
        if interface_service.ethernet.config.port_speed:
            speeds_oc_to_xe = {
                'SPEED_10MB': '10',
                'SPEED_100MB': '100',
                'SPEED_1GB': '1000',
                'SPEED_10GB': '10000'
            }
            interface_cdb.speed = speeds_oc_to_xe.get(interface_service.ethernet.config.port_speed)
        # enable-flow-control
        if interface_service.ethernet.config.enable_flow_control is True:
            interface_cdb.flowcontrol.receive = 'on'
        elif interface_service.ethernet.config.enable_flow_control is False:
            interface_cdb.flowcontrol.receive = None
        # mac-address
        if interface_service.ethernet.config.mac_address:
            xe_mac = f'{interface_service.ethernet.config.mac_address[0:2]}\
            {interface_service.ethernet.config.mac_address[3:5]}.\
            {interface_service.ethernet.config.mac_address[6:8]}\
            {interface_service.ethernet.config.mac_address[9:11]}.\
            {interface_service.ethernet.config.mac_address[12:14]}\
            {interface_service.ethernet.config.mac_address[15:17]}'
            interface_cdb.mac_address = xe_mac
        # # poe  TODO
        # if interface_service.ethernet.poe.config.enabled is True:
        #     interface_cdb.power.inline.mode = 'auto'
        # elif interface_service.ethernet.poe.config.enabled is False:
        #     interface_cdb.power.inline.mode = 'never'

        # switched-vlan interface-mode
        if interface_service.ethernet.switched_vlan.config.interface_mode:
            self.xe_configure_switched_vlan(interface_cdb, interface_service.ethernet.switched_vlan)
        else:
            if interface_cdb.switchport.exists():
                interface_cdb.switchport.delete()
        if interface_service.ethernet.config.aggregate_id:
            interface_cdb.channel_group.number = self.xe_get_port_channel_number(
                interface_service.ethernet.config.aggregate_id)
            interface_cdb.channel_group.mode = 'active'

    def xe_interface_aggregation(self, interface_service: ncs.maagic.ListElement,
                                 interface_cdb: ncs.maagic.ListElement):
        if interface_service.aggregation.config.min_links:
            interface_cdb.port_channel.min_links = int(interface_service.aggregation.config.min_links)

        # switched-vlan interface-mode
        if interface_service.aggregation.switched_vlan.config.interface_mode:
            self.xe_configure_switched_vlan(interface_cdb, interface_service.aggregation.switched_vlan)
        else:
            if interface_cdb.switchport.exists():
                interface_cdb.switchport.delete()
        if interface_service.aggregation.ipv4:
            self.xe_configure_ipv4(interface_cdb, interface_service.aggregation.ipv4)

    def xe_reconcile_vlan_db(self):
        """
        Ensure device VLAN DB is in sync with incoming configs
        """

        # Get VLANs from device VLAN DB
        vlans_device_db = list()
        for v in self.root.devices.device[self.service.name].config.ios__vlan.vlan_list:
            vlans_device_db.append(v.id)
        self.log.info(f'VLANs in device DB: {vlans_device_db}')

        # Get VLANs from incoming configs
        vlans_in_model_configs = list()
        for v in self.service.openconfig_interfaces.interfaces.interface:
            if v.aggregation.switched_vlan.config.access_vlan:
                vlans_in_model_configs.append(v.aggregation.switched_vlan.config.access_vlan)
            for x in v.aggregation.switched_vlan.config.trunk_vlans:
                if x:
                    vlans_in_model_configs.append(x)
            for x in v.ethernet.switched_vlan.config.trunk_vlans:
                if x:
                    vlans_in_model_configs.append(x)
            if v.ethernet.switched_vlan.config.native_vlan:
                vlans_in_model_configs.append(v.ethernet.switched_vlan.config.native_vlan)
            if v.routed_vlan.config.vlan:
                vlans_in_model_configs.append(v.routed_vlan.config.vlan)
        self.log.info(f'VLANs from configs: {vlans_in_model_configs}')

        # Find VLANs to remove from device VLAN DB
        vlans_to_remove_from_db = [v for v in vlans_device_db if v not in set(vlans_in_model_configs)]
        self.log.info(f'vlans_to_remove_from_db: {vlans_to_remove_from_db}')

        # Delete VLANs from VLAN DB
        for v in vlans_to_remove_from_db:
            if v != 1:  # don't try to delete VLAN 1
                del self.root.devices.device[self.service.name].config.ios__vlan.vlan_list[v]

        # Find VLANs to create in device VLAN DB
        vlans_to_create_in_db = [v for v in vlans_in_model_configs if v not in set(vlans_device_db)]
        self.log.info(f'vlans_to_create_in_db: {vlans_to_create_in_db}')

        # Create VLANs in device VLAN DB
        for v in vlans_to_create_in_db:
            self.root.devices.device[self.service.name].config.ios__vlan.vlan_list.create(v)
            vlan = self.root.devices.device[self.service.name].config.ios__vlan.vlan_list[v]
            if vlan.shutdown.exists():
                vlan.shutdown.delete()

    def xe_reconcile_vlan_interfaces(self):
        """
        Ensure device does not have extra VLAN interfaces
        """
        # Get all device VLAN interfaces
        vlan_interfaces_existing = list()
        for v in self.root.devices.device[self.service.name].config.ios__interface.Vlan:
            vlan_interfaces_existing.append(v.name)
        self.log.info(f'VLAN interfaces existing: {vlan_interfaces_existing}')

        # Get all VLAN interfaces from incoming configs
        vlan_interfaces_proposed = list()
        for v in self.service.openconfig_interfaces.interfaces.interface:
            if v.config.type == 'ianaift:l3ipvlan':
                vlan_interfaces_proposed.append(v.routed_vlan.config.vlan)
        self.log.info(f'VLANs proposed: {vlan_interfaces_proposed}')

        # Find VLAN interfaces to remove
        vlan_interfaces_to_remove = [v for v in vlan_interfaces_existing if v not in set(vlan_interfaces_proposed)]
        self.log.info(f'VLANs to remove: {vlan_interfaces_to_remove}')

        # Delete VLAN interfaces
        if vlan_interfaces_to_remove:
            for v in vlan_interfaces_to_remove:
                del self.root.devices.device[self.service.name].config.ios__interface.Vlan[v]

    def xe_reconcile_port_channel_interfaces(self):
        """
        Ensure device does not have extra port channel interfaces
        """
        # Get all device port-channel interfaces
        port_channel_interfaces_existing = list()
        for p in self.root.devices.device[self.service.name].config.ios__interface.Port_channel:
            port_channel_interfaces_existing.append(p.name)
        self.log.info(f'Port channel interfaces existing: {port_channel_interfaces_existing}')

        # Get all port-channel interfaces from incoming configs
        port_channel_interfaces_proposed = list()
        for p in self.service.openconfig_interfaces.interfaces.interface:
            if p.config.type == 'ianaift:ieee8023adLag':
                port_channel_number = self.xe_get_port_channel_number(p.name)
                port_channel_interfaces_proposed.append(port_channel_number)
        self.log.info(f'Port channel interfaces proposed: {port_channel_interfaces_proposed}')

        # Find port-channel interfaces to remove
        port_channel_interfaces_to_remove = [p for p in port_channel_interfaces_existing if
                                             p not in set(port_channel_interfaces_proposed)]
        self.log.info(f'Port-channels to remove: {port_channel_interfaces_to_remove}')

        # Delete port-channel interfaces
        if port_channel_interfaces_to_remove:
            for p in port_channel_interfaces_to_remove:
                del self.root.devices.device[self.service.name].config.ios__interface.Port_channel[p]

    def xe_reconcile_sub_interfaces(self):
        """
        Ensure device does not have extra sub-interfaces defined
        """
        # Get all sub interfaces from CDB
        sub_interfaces_existing = self.xe_get_subinterfaces()
        self.log.info(f'Sub interfaces existing: {sub_interfaces_existing}')

        # Get all sub interfaces from incoming configs
        sub_interfaces_proposed = list()
        for s in self.service.openconfig_interfaces.interfaces.interface:
            if s.subinterfaces.subinterface:
                for si in s.subinterfaces.subinterface:
                    if si.index and si.index != 0:
                        sub_interfaces_proposed.append(s.name + '.' + str(si.index))
        self.log.info(f'Sub interfaces proposed: {sub_interfaces_proposed}')

        # Find Sub interfaces to remove
        sub_interfaces_to_remove = [si for si in sub_interfaces_existing if si not in set(sub_interfaces_proposed)]
        self.log.info(f'Sub interfaces to remove: {sub_interfaces_to_remove}')

        # Delete Sub interfaces
        if sub_interfaces_to_remove:
            for si in sub_interfaces_to_remove:
                rt = re.search(r"\D+", si)
                interface_type = rt.group(0)
                rn = re.search(r"[0-9]+(\/[0-9]+)*\.[0-9]+", si)
                interface_number = rn.group(0)
                class_attribute = getattr(self.root.devices.device[self.service.name].config.ios__interface,
                                          interface_type)
                del class_attribute[interface_number]

    def xe_transform_vars(self):
        """
        Transforms values into appropriate format IOS XE template values.
        """
        pass

    # @staticmethod
    def xe_configure_ipv4(self, interface_cdb: ncs.maagic.ListElement, service_ipv4: ncs.maagic.Container):
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
        if not service_ipv4.config.dhcp_client:
            interface_cdb.ip.address.dhcp.delete()
        # proxy-arp
        if service_ipv4.proxy_arp.config.mode == 'DISABLE' or not service_ipv4.proxy_arp.config.mode:
            interface_cdb.ip.proxy_arp = False
        if service_ipv4.proxy_arp.config.mode == 'REMOTE_ONLY':
            interface_cdb.ip.proxy_arp = True

    @staticmethod
    def xe_configure_switched_vlan(interface_cdb: ncs.maagic.ListElement,
                                   service_switched_vlan: ncs.maagic.Container):
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

    @staticmethod
    def xe_interface_config(interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement):
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

    @staticmethod
    def xe_interface_hold_time(interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement):
        if interface_service.hold_time.config.down:
            interface_cdb.carrier_delay.msec = int(interface_service.hold_time.config.down)

    @staticmethod
    def xe_get_interface_type_and_number(interface: str) -> Tuple[str, str]:
        """
        Receive full interface name. Returns interface type and number.
        :param interface: full interface name
        :return: tuple of interface type, interface number
        """
        rt = re.search(r"\D+", interface)
        interface_name = rt.group(0)
        rn = re.search(r"[0-9]+(\/[0-9]+)*", interface)
        interface_number = rn.group(0)
        return interface_name, interface_number

    @staticmethod
    def xe_get_port_channel_number(interface: str) -> int:
        pn = re.search(r"\d+", interface)
        return int(pn.group(0))

    @staticmethod
    def update_vars(initial_vars: dict, proplist: list) -> dict:
        """
        Updates initial vars with transformed vars
        :param initial_vars: dictionary of template variables
        :param proplist: list of tuples containing template variable to value
        :return: dictionary of template variable names to values
        """
        if proplist:
            for var_tuple in proplist:
                if var_tuple[0] in initial_vars:
                    initial_vars[var_tuple[0]] = var_tuple[1]
        return initial_vars


class Main(ncs.application.Application):
    def setup(self):
        self.log.info('Main RUNNING')
        self.register_service('oc-interfaces-nso-servicepoint', ServiceCallbacks)

    def teardown(self):
        self.log.info('Main FINISHED')