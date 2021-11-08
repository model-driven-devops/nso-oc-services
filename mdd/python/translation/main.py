# -*- mode: python; python-indent: 4 -*-
import re

import ncs
import _ncs
from ncs.application import Service
from translation.openconfig_xe.xe_acls import xe_acls_program_service
from translation.openconfig_xe.xe_acls import xe_acls_interfaces_program_service
from translation.openconfig_xe.xe_acls import xe_acls_lines_program_service
from translation.openconfig_xe.xe_acls import xe_acls_ntp_program_service
from translation.openconfig_xe.xe_routing_policy import xe_routing_policy_program_service
from translation.openconfig_xe.xe_interfaces import xe_interfaces_program_service
from translation.openconfig_xe.xe_network_instances import xe_network_instances_program_service
from translation.openconfig_xe.xe_system import xe_system_transform_vars
from translation.openconfig_xe.xe_system import xe_system_initial_vars
from translation.openconfig_xe.xe_system import xe_system_program_service

regex_device = re.compile(r'device{(.*)}\/')


class OCCallback(Service):
    @Service.create
    def cb_create(self, tctx: _ncs.TransCtxRef, root: ncs.maagic.Root, service: ncs.maagic.ListElement, proplist: list):
        self.log.info(f'Service create(service={service._path})')
        self.service = service
        self.root = root
        self.proplist = proplist
        # Get device name from service path
        r = regex_device.search(service._path)
        self.device_name = r.group(1)

        # Each NED may have a template and will have python processing code
        if 'cisco-ios-cli' in self.root.devices.device[self.device_name].device_type.cli.ned_id:
            # OpenConfig Interfaces
            if len(service.oc_if__interfaces.interface) > 0:
                xe_interfaces_program_service(self)

            # OpenConfig ACL
            if len(service.oc_acl__acl.acl_sets.acl_set) > 0:
                xe_acls_program_service(self)
            if len(service.oc_acl__acl.interfaces.interface) > 0:
                xe_acls_interfaces_program_service(self)
            if len(service.oc_acl__acl.oc_acl_ext__lines.line) > 0:
                xe_acls_lines_program_service(self)
            xe_acls_ntp_program_service(self)

            # OpenConfig routing-policy
            if service.oc_rpol__routing_policy:
                xe_routing_policy_program_service(self)

            # OpenConfig Network Instances
            if len(service.oc_netinst__network_instances.network_instance) > 0:
                xe_network_instances_program_service(self)

            # OpenConfig System
            xe_system_transform_vars(self)
            self.log.info(self.proplist)
            xe_final_vars = update_vars(xe_system_initial_vars, self.proplist)
            xe_final_vars['DEVICE'] = self.device_name
            xe_vars_template = ncs.template.Variables()
            for k in xe_final_vars:
                xe_vars_template.add(k, xe_final_vars[k])
            template = ncs.template.Template(service)
            template.apply('xe-system-template', xe_vars_template)

            xe_system_program_service(self)


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
        self.register_service('oc-servicepoint', OCCallback)

    def teardown(self):
        self.log.info('Main FINISHED')
