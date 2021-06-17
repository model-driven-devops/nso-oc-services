# -*- mode: python; python-indent: 4 -*-
import ipaddress

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
            if i.config.type == 'ianaift:l3ipvlan':
                if not self.root.devices.device[self.service.name].config.ios__interface.Vlan.exists(
                        i.routed_vlan.config.vlan):
                    self.root.devices.device[self.service.name].config.ios__interface.Vlan.create(
                        i.routed_vlan.config.vlan)

                vlan = self.root.devices.device[self.service.name].config.ios__interface.Vlan[
                    i.routed_vlan.config.vlan]
                vlan.description = i.config.description
                if i.config.enabled:
                    if vlan.shutdown.exists():
                        vlan.shutdown.delete()
                else:
                    vlan.shutdown.create()

                ips_and_masks = list()
                if i.routed_vlan.ipv4.addresses.address:
                    vlan.ip.address.dhcp.delete()
                    for a in i.routed_vlan.ipv4.addresses.address:
                        ip = ipaddress.ip_network(f'10.0.0.0/{a.config.prefix_length}')
                        ips_and_masks.append(dict(ip=a.config.ip, sm=str(ip.netmask)))

                    for counter, ip_dict in enumerate(ips_and_masks):
                        self.log.info(f'ips_and_masks {counter} {ip_dict}')
                        if counter == 0:
                            vlan.ip.address.primary.address = ip_dict.get('ip')
                            vlan.ip.address.primary.mask = ip_dict.get('sm')
                        if counter > 0:  # TODO Add any secondary IP addresses
                            pass
                else:
                    if i.routed_vlan.ipv4.config.dhcp_client:
                        vlan.ip.address.dhcp.create()
                if not i.routed_vlan.ipv4.config.dhcp_client:
                    vlan.ip.address.dhcp.delete()

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
