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

                # Get current cdb addresses
                ips_and_masks_cdb = list()
                for x in vlan.ip.address.secondary:
                    ips_and_masks_cdb.append((x.address, x.mask))

                # Create service config address mask list
                ips_and_masks = list()
                if i.routed_vlan.ipv4.addresses.address:
                    vlan.ip.address.dhcp.delete()
                    for a in i.routed_vlan.ipv4.addresses.address:
                        ip = ipaddress.ip_network(f'10.0.0.0/{a.config.prefix_length}')
                        ips_and_masks.append((a.config.ip, str(ip.netmask)))

                    # Remove unrequested IPs from CDB
                    ips_to_remove = list()
                    for ips in ips_and_masks_cdb:
                        if ips not in ips_and_masks[1:]:
                            ips_to_remove.append(ips)
                    for ips in ips_to_remove:
                        del vlan.ip.address.secondary[ips]

                    # Update/Create needed IP addresses in CDB
                    for counter, ip_mask in enumerate(ips_and_masks):
                        self.log.info(f'ips_and_masks {counter} {ip_mask}')
                        if counter == 0:
                            vlan.ip.address.primary.address = ip_mask[0]
                            vlan.ip.address.primary.mask = ip_mask[1]
                        # elif counter > 0: TODO
                        #     if not vlan.ip.address.secondary.exists(ip_mask):
                        #         vlan.ip.address.secondary.create(ip_mask)
                else:
                    if i.routed_vlan.ipv4.config.dhcp_client:
                        vlan.ip.address.dhcp.create()
                if not i.routed_vlan.ipv4.config.dhcp_client:
                    vlan.ip.address.dhcp.delete()

            # Layer 2 interfaces
            if i.config.type == 'ianaift:l2vlan' and i.ethernet.switched_vlan.config.interface_mode == 'TRUNK':
                interface_type, interface_number = self.xe_get_interface_type_and_number(i.config.name)
                class_attribute = getattr(self.root.devices.device[self.service.name].config.ios__interface,
                                          interface_type)
                l2_interface = class_attribute[interface_number]
                self.xe_interface_config(i, l2_interface)
                self.xe_interface_hold_time(i, l2_interface)
                self.xe_interface_ethernet(i, l2_interface)

    @staticmethod
    def xe_interface_hold_time(interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement):
        if interface_service.hold_time.config.down:
            interface_cdb.carrier_delay.msec = int(interface_service.hold_time.config.down)

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
    def xe_interface_ethernet(interface_service: ncs.maagic.ListElement, interface_cdb: ncs.maagic.ListElement):
        # # aggregate-id TODO
        # if interface_service.ethernet.config.aggregate_id:
        #     interface_cdb.description = interface_service.ethernet.config.aggregate_id
        # auto-negotiate
        if interface_service.ethernet.config.auto_negotiate:
            interface_cdb.negotiation.auto = interface_service.ethernet.config.auto_negotiate
            # interface_cdb.duplex = 'auto'
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
            if interface_service.ethernet.switched_vlan.config.interface_mode == 'TRUNK':
                if not interface_cdb.switchport.exists():
                    interface_cdb.switchport.create()
                interface_cdb.switchport.trunk.encapsulation = 'dot1q'
                if not interface_cdb.switchport.mode.trunk.exists():
                    interface_cdb.switchport.mode.trunk.create()
                if interface_service.ethernet.switched_vlan.config.native_vlan:
                    interface_cdb.switchport.trunk.native.vlan = int(interface_service.ethernet.switched_vlan.config.native_vlan)
                elif interface_service.ethernet.switched_vlan.config.native_vlan == '':
                    interface_cdb.switchport.trunk.native.vlan = None
                # Reconcile trunked VLANs
                allowed_vlans_cdb = [v for v in interface_cdb.switchport.trunk.allowed.vlan.vlans]
                allowed_vlans_config = [int(v) for v in interface_service.ethernet.switched_vlan.config.trunk_vlans]
                # Remove unspecified VLANs
                for v in allowed_vlans_cdb:
                    if v not in allowed_vlans_config:
                        interface_cdb.switchport.trunk.allowed.vlan.vlans.remove(v)
                # Added specified VLANs
                for v in allowed_vlans_config:
                    if v not in allowed_vlans_cdb:
                        interface_cdb.switchport.trunk.allowed.vlan.vlans.create(v)
            elif interface_service.ethernet.switched_vlan.config.interface_mode == 'ACCESS':
                if not interface_cdb.switchport.exists():
                    interface_cdb.switchport.create()
                if not interface_cdb.switchport.mode.access.exists():
                    interface_cdb.switchport.mode.access.create()
                if interface_service.ethernet.switched_vlan.config.access_vlan:
                    interface_cdb.switchport.access.vlan = int(interface_service.ethernet.switched_vlan.config.access_vlan)

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

    def xe_reconcile_vlan_db(self):
        """
        Ensure device VLAN DB is in sync with incoming configs
        """

        # Get VLANs from device VLAN DB
        vlans_device_db = list()
        for v in self.root.devices.device[self.service.name].config.ios__vlan.vlan_list:
            vlans_device_db.append(v.id)
        self.log.info(f'VLANs in device DB: {vlans_device_db}')

        # Get VLANs from incoming configs  TODO Keep this up to date
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
            if v != 1:
                del self.root.devices.device[self.service.name].config.ios__vlan.vlan_list[v]

        # Find VLANs to create in device VLAN DB
        vlans_to_create_in_db = [v for v in vlans_in_model_configs if v not in set(vlans_device_db)]
        self.log.info(f'vlans_to_create_in_db: {vlans_to_create_in_db}')

        # Create VLANs in device VLAN DB
        for v in vlans_to_create_in_db:
            self.root.devices.device[self.service.name].config.ios__vlan.vlan_list.create(v)
            vlan = self.root.devices.device[self.service.name].config.ios__vlan.vlan_list[v]
            try:
                vlan.shutdown.delete()
            except:
                pass

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

    def xe_transform_vars(self):
        """
        Transforms values into appropriate format IOS XE template values.
        """
        pass

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
