# -*- mode: python; python-indent: 4 -*-
import re

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

        initial_vars = dict(XE_TIMEZONE='',
                            XE_TIMEZONE_OFFSET_HOURS='',
                            XE_TIMEZONE_OFFSET_MINUTES='',
                            XE_NTP_SOURCE_INF_TYPE='',
                            XE_NTP_SOURCE_INF_NUMBER='')

        proplist = self.xe_transform_vars(service, proplist)
        self.log.info(proplist)

        final_vars = self.update_vars(initial_vars, proplist)
        vars_template = ncs.template.Variables()
        for k in final_vars:
            vars_template.add(k, final_vars[k])
        template = ncs.template.Template(service)
        template.apply('oc-system-nso-template', vars_template)

    def xe_transform_vars(self, service_object: ncs.maagic.ListElement, proplist: list) -> list:
        """
        Receives variables from service and transforms values into appropriate format IOS XE template values.
        :param service_object: ncs.maagic.ListElement of current service
        :param proplist: list of template values
        :return: list of updated template values
        """
        if service_object.openconfig_system.system.clock.config.timezone_name:
            tz = service_object.openconfig_system.system.clock.config.timezone_name.split()
            if len(tz) != 3:
                raise ValueError
            else:
                proplist.append(('XE_TIMEZONE', tz[0]))
            if -12 > int(tz[1]) or int(tz[1]) > 12:
                raise ValueError
            else:
                proplist.append(('XE_TIMEZONE_OFFSET_HOURS', tz[1]))
            if 0 > int(tz[2]) or int(tz[2]) > 60:
                raise ValueError
            else:
                proplist.append(('XE_TIMEZONE_OFFSET_MINUTES', tz[2]))
        if service_object.openconfig_system.system.ntp.config.ntp_source_address:
            output = self.xe_show_commands('ip interface brief | e unassigned|Interface', service_object.name)
            ip_name_dict = self.xe_get_interface_ip_address(output, service_object.name)
            if ip_name_dict[service_object.openconfig_system.system.ntp.config.ntp_source_address]:
                rt = re.search(r"\D+", ip_name_dict.get(service_object.openconfig_system.system.ntp.config.ntp_source_address, ""))
                interface_name = rt.group(0)
                rn = re.search(r"[0-9]+(\/[0-9]+)*", ip_name_dict.get(service_object.openconfig_system.system.ntp.config.ntp_source_address, ""))
                interface_number = rn.group(0)
                proplist.append(('XE_NTP_SOURCE_INF_TYPE', interface_name))
                proplist.append(('XE_NTP_SOURCE_INF_NUMBER', interface_number))
        return proplist

    @staticmethod
    def update_vars(initial_vars: dict, proplist: list) -> dict:
        """
        Updates initial vars with transformed vars
        :param initial_vars: dictionary of template vaiables
        :param proplist: list of tuples containing template variable to value
        :return: dictionary of template variable names to values
        """
        if proplist:
            for var_tuple in proplist:
                if var_tuple[0] in initial_vars:
                    initial_vars[var_tuple[0]] = var_tuple[1]
        return initial_vars

    @staticmethod
    def xe_show_commands(command: str, device_name: str) -> str:
        """
        Receives IOS XE show command and returns output
        :param command: str of command, i.e. ip interface brief
        :param device_name: str name of device
        :return: output of command
        """
        with ncs.maapi.Maapi() as m:
            with ncs.maapi.Session(m, 'admin', 'python'):
                root = ncs.maagic.get_root(m)
                device = root.devices.device[device_name]
                input1 = device.live_status.ios_stats__exec.show.get_input()
                input1.args = [command]
                return device.live_status.ios_stats__exec.show(input1).result

    @staticmethod
    def xe_get_interface_ip_address(op: str, device: str) -> dict:
        """
        Receives output of show ip interface brief and device name and returns a dictionary of
        IPs and interface names, e.g. {'172.16.255.1: 'Loopback0', '192.168.1.1': 'GigabitEthernet1'}
        :param op: str output from 'show ip interface brief'
        :param device: str name of device
        :return: dictionary of ips to interface names
        """
        ip_name_dict = dict()
        output_lines = op.split('\n')
        for i in output_lines:
            n = i.split()
            if len(n) > 0:
                if n[0] != (device + '#'):
                    ip_name_dict[n[1]] = n[0]
        return ip_name_dict


class Main(ncs.application.Application):
    def setup(self):
        self.log.info('Main RUNNING')
        self.register_service('oc-system-nso-servicepoint', ServiceCallbacks)

    def teardown(self):
        self.log.info('Main FINISHED')
