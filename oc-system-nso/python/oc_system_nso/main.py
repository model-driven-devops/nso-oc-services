# -*- mode: python; python-indent: 4 -*-
import re

import ncs
import _ncs
from ncs.application import Service
from typing import Tuple


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
                            XE_NTP_SOURCE_INF_NUMBER='',
                            XE_EXEC_TIMEOUT_MINUTES='',
                            XE_EXEC_TIMEOUT_SECONDS='',
                            XE_CONSOLE_FACILITY='',
                            XE_CONSOLE_SEVERITY='',
                            XE_REMOTE_FACILITY='',
                            XE_REMOTE_SEVERITY='',
                            XE_LOGGING_SOURCE_INF_NAME='',
                            XE_AUTHENTICATION_TACACS='',
                            XE_AUTHENTICATION_LOCAL='',
                            XE_AUTHORIZATION_TACACS='',
                            XE_AUTHORIZATION_LOCAL='',
                            XE_AUTHORIZATION_AAA_AUTHORIZATION_EVENT_CONFIG='',
                            XE_AUTHORIZATION_AAA_AUTHORIZATION_EVENT_COMMAND='',
                            XE_TACACS_SOURCE_INF_TYPE='',
                            XE_TACACS_SOURCE_INF_NUMBER='')

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
                interface_name, interface_number = self.xe_get_interface_name_and_number(ip_name_dict,
                                                                                         service_object.openconfig_system.system.ntp.config.ntp_source_address)
                proplist.append(('XE_NTP_SOURCE_INF_TYPE', interface_name))
                proplist.append(('XE_NTP_SOURCE_INF_NUMBER', interface_number))
        if service_object.openconfig_system.system.ssh_server.config.timeout:
            seconds_all = int(service_object.openconfig_system.system.ssh_server.config.timeout)
            proplist.append(('XE_EXEC_TIMEOUT_MINUTES', str(seconds_all // 60)))
            proplist.append(('XE_EXEC_TIMEOUT_SECONDS', str(seconds_all % 60)))
        if service_object.openconfig_system.system.logging.console.selectors.selector:
            for i in service_object.openconfig_system.system.logging.console.selectors.selector:
                proplist.append(('XE_CONSOLE_FACILITY', str(i.facility).lower().replace('oc-log:', '')))
                proplist.append(('XE_CONSOLE_SEVERITY', str(i.severity).lower()))
                break
        if service_object.openconfig_system.system.logging.remote_servers.remote_server:
            need_remote_facility = True
            need_remote_severity = True
            need_source_address = True
            for n in service_object.openconfig_system.system.logging.remote_servers.remote_server:
                for i in n.selectors.selector:
                    if need_remote_facility:
                        proplist.append(('XE_REMOTE_FACILITY', str(i.facility).lower().replace('oc-log:', '')))
                        need_remote_facility = False
                    if need_remote_severity:
                        proplist.append(('XE_REMOTE_SEVERITY', str(i.severity).lower()))
                        need_remote_severity = False
                if need_source_address and n.config.source_address:
                    output = self.xe_show_commands('ip interface brief | e unassigned|Interface', service_object.name)
                    ip_name_dict = self.xe_get_interface_ip_address(output, service_object.name)
                    if ip_name_dict[n.config.source_address]:
                        interface_name, interface_number = self.xe_get_interface_name_and_number(ip_name_dict,
                                                                                                 n.config.source_address)
                        proplist.append(('XE_LOGGING_SOURCE_INF_NAME', f'{interface_name}{interface_number}'))
                        need_source_address = False
        if service_object.openconfig_system.system.aaa.authentication.config.authentication_method:
            for i in service_object.openconfig_system.system.aaa.authentication.config.authentication_method:
                if i == 'TACACS_ALL':
                    proplist.append(('XE_AUTHENTICATION_TACACS', 'True'))
                elif i == 'LOCAL':
                    proplist.append(('XE_AUTHENTICATION_LOCAL', 'True'))
        if service_object.openconfig_system.system.aaa.authorization.config.authorization_method:
            for i in service_object.openconfig_system.system.aaa.authorization.config.authorization_method:
                if i == 'TACACS_ALL':
                    proplist.append(('XE_AUTHORIZATION_TACACS', 'True'))
                elif i == 'LOCAL':
                    proplist.append(('XE_AUTHORIZATION_LOCAL', 'True'))
        if service_object.openconfig_system.system.aaa.authorization.events.event:
            for i in service_object.openconfig_system.system.aaa.authorization.events.event:
                if i.event_type == 'oc-aaa-types:AAA_AUTHORIZATION_EVENT_CONFIG':
                    proplist.append(('XE_AUTHORIZATION_AAA_AUTHORIZATION_EVENT_CONFIG', 'True'))
                if i.event_type == 'oc-aaa-types:AAA_AUTHORIZATION_EVENT_COMMAND':
                    proplist.append(('XE_AUTHORIZATION_AAA_AUTHORIZATION_EVENT_COMMAND', 'True'))
        for i in service_object.openconfig_system.system.aaa.server_groups.server_group:
            for n in i.servers.server:
                if n.tacacs.config.source_address:
                    output = self.xe_show_commands('ip interface brief | e unassigned|Interface', service_object.name)
                    ip_name_dict = self.xe_get_interface_ip_address(output, service_object.name)
                    if ip_name_dict[n.tacacs.config.source_address]:
                        interface_name, interface_number = self.xe_get_interface_name_and_number(ip_name_dict,
                                                                                                 n.tacacs.config.source_address)
                        proplist.append(('XE_TACACS_SOURCE_INF_TYPE', interface_name))
                        proplist.append(('XE_TACACS_SOURCE_INF_NUMBER', interface_number))
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

    @staticmethod
    def xe_get_interface_name_and_number(ip_name_d: dict, ip: str) -> Tuple[str, str]:
        """
        Receive dictionary of IPs to interface names and IP. Returns interface type and number associated with IP.
        :param ip_name_d: dictionary of IPs to interface names
        :param ip: string IP to be match to interface name
        :return: tuple of interface type, interaface number
        """
        rt = re.search(r"\D+", ip_name_d.get(ip, ""))
        interface_name = rt.group(0)
        rn = re.search(r"[0-9]+(\/[0-9]+)*", ip_name_d.get(ip, ""))
        interface_number = rn.group(0)
        return interface_name, interface_number


class Main(ncs.application.Application):
    def setup(self):
        self.log.info('Main RUNNING')
        self.register_service('oc-system-nso-servicepoint', ServiceCallbacks)

    def teardown(self):
        self.log.info('Main FINISHED')
