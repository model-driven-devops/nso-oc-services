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

        self.service = service
        self.root = root
        self.proplist = proplist

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
                            XE_AUTHORIZATION_AAA_AUTHORIZATION_EVENT_COMMAND='')

        # Each NED type with have a x_transform_vars here
        self.xe_transform_vars()
        final_vars = self.update_vars(initial_vars, self.proplist)
        vars_template = ncs.template.Variables()
        for k in final_vars:
            vars_template.add(k, final_vars[k])
        template = ncs.template.Template(service)
        template.apply('oc-system-nso-template', vars_template)

        # Each NED type may have a x_program_server here
        self.xe_program_service()

    def xe_program_service(self):
        """
        Program service for xe NED features too complex for XML template.
        Includes:
            - aaa accounting
            - aaa server-groups
        """
        ### aaa accounting
        aaa_accounting_accounting_methods = list()
        aaa_accounting_events = list()
        if self.service.openconfig_system.system.aaa.accounting.config.accounting_method:
            for i in self.service.openconfig_system.system.aaa.accounting.config.accounting_method:
                aaa_accounting_accounting_methods.append(i)
        if self.service.openconfig_system.system.aaa.accounting.events.event:
            for i in self.service.openconfig_system.system.aaa.accounting.events.event:
                aaa_accounting_events.append(
                    {"config": {"event-type": i['config']['event-type'], "record": i['config']['record']},
                     "event-type": i['event-type']})
        if aaa_accounting_accounting_methods and aaa_accounting_events:
            for e in aaa_accounting_events:
                self.log.info(e)
                if e['event-type'] == 'oc-aaa-types:AAA_ACCOUNTING_EVENT_COMMAND':
                    if self.root.devices.device[self.service.name].config.ios__aaa.accounting.commands.exists(
                            ("15", "default")):
                        event = self.root.devices.device[self.service.name].config.ios__aaa.accounting.commands[
                            ("15", "default")]
                    else:
                        event = self.root.devices.device[self.service.name].config.ios__aaa.accounting.commands.create(
                            ("15", "default"))

                    if e['config']['record'] == "STOP":
                        event.action_type = 'stop-only'
                    elif e['config']['record'] == "START_STOP":
                        event.action_type = 'start-stop'

                    counter = 0
                    for m in aaa_accounting_accounting_methods:
                        if m == "TACACS_ALL":
                            method = "tacacs+"
                        else:
                            method = m
                        if counter == 0:
                            event['group'] = method
                            counter += 1
                        elif counter == 1:
                            event['group2']['group'] = method
                            counter += 1
                        elif counter == 2:
                            event['group3']['group'] = method
                            counter += 1
                if e['event-type'] == 'oc-aaa-types:AAA_ACCOUNTING_EVENT_LOGIN':
                    if self.root.devices.device[self.service.name].config.ios__aaa.accounting.exec.exists(("default")):
                        event = self.root.devices.device[self.service.name].config.ios__aaa.accounting.exec[("default")]
                    else:
                        event = self.root.devices.device[self.service.name].config.ios__aaa.accounting.exec.create(
                            ("default"))

                    if e['config']['record'] == "STOP":
                        self.log.info('YES IT IS STOP')
                        event.action_type = 'stop-only'
                    elif e['config']['record'] == "START_STOP":
                        self.log.info('YES IT IS START_STOP')
                        event.action_type = 'start-stop'

                    counter = 0
                    for m in aaa_accounting_accounting_methods:
                        if m == "TACACS_ALL":
                            method = "tacacs+"
                        else:
                            method = m
                        if counter == 0:
                            event['group'] = method
                            counter += 1
                        elif counter == 1:
                            event['group2']['group'] = method
                            counter += 1
                        elif counter == 2:
                            event['group3']['group'] = method
                            counter += 1

        ### aaa server-groups
        if self.service.openconfig_system.system.aaa.server_groups.server_group:
            server_groups = list()
            for group in self.service.openconfig_system.system.aaa.server_groups.server_group:
                server_group = dict(name=group.name, type=group.config.type, servers=[])
                for server in group.servers.server:
                    server_info = dict(address=server.address,
                                       name=server.config.name,
                                       timeout=server.config.timeout,
                                       port=server.tacacs.config.port,
                                       secret_key=server.tacacs.config.secret_key,
                                       source_address=server.tacacs.config.source_address)
                    server_group['servers'].append(server_info)
                server_groups.append(server_group)
            self.log.info(server_groups)
            for g in server_groups:
                source_address = ''
                for s in g['servers']:
                    if self.root.devices.device[self.service.name].config.ios__tacacs.server.exists((s.get('name'))):
                        server = self.root.devices.device[self.service.name].config.ios__tacacs.server[(s.get('name'))]
                    else:
                        server = self.root.devices.device[self.service.name].config.ios__tacacs.server.create(s.get('name'))

                    if s.get('address'): server.address.ipv4 = s.get('address')
                    server.key.type = '0'
                    if s.get('secret_key'): server.key.secret = s.get('secret_key')
                    if server.timeout: server.timeout = s.get('timeout')
                    if s.get('port'): server.port = s.get('port')
                    if s.get('source_address'): source_address = s.get('source_address')

                if self.root.devices.device[self.service.name].config.ios__aaa.group.server.tacacs_plus.exists((g.get('name'))):
                    group = self.root.devices.device[self.service.name].config.ios__aaa.group.server.tacacs_plus[(g.get('name'))]
                else:
                    group = self.root.devices.device[self.service.name].config.ios__aaa.group.server.tacacs_plus.create((g.get('name')))

                for s in g['servers']:
                    if not group.server.name.exists(s.get('name')):
                        group.server.name.create(s.get('name'))
                if source_address:
                    ip_name_dict = self.xe_get_interface_ip_address()
                    if ip_name_dict[source_address]:
                        interface_name, interface_number = self.xe_get_interface_name_and_number(ip_name_dict,
                                                                                                 source_address)
                        setattr(group.ip.tacacs.source_interface, interface_name, interface_number)

    def xe_transform_vars(self):
        """
        Transforms values into appropriate format IOS XE template values.
        """
        if self.service.openconfig_system.system.clock.config.timezone_name:
            tz = self.service.openconfig_system.system.clock.config.timezone_name.split()
            if len(tz) != 3:
                raise ValueError
            else:
                self.proplist.append(('XE_TIMEZONE', tz[0]))
            if -12 > int(tz[1]) or int(tz[1]) > 12:
                raise ValueError
            else:
                self.proplist.append(('XE_TIMEZONE_OFFSET_HOURS', tz[1]))
            if 0 > int(tz[2]) or int(tz[2]) > 60:
                raise ValueError
            else:
                self.proplist.append(('XE_TIMEZONE_OFFSET_MINUTES', tz[2]))
        if self.service.openconfig_system.system.ntp.config.ntp_source_address:
            ip_name_dict = self.xe_get_interface_ip_address()
            if ip_name_dict[self.service.openconfig_system.system.ntp.config.ntp_source_address]:
                interface_name, interface_number = self.xe_get_interface_name_and_number(ip_name_dict,
                                                                                         self.service.openconfig_system.system.ntp.config.ntp_source_address)
                self.proplist.append(('XE_NTP_SOURCE_INF_TYPE', interface_name))
                self.proplist.append(('XE_NTP_SOURCE_INF_NUMBER', interface_number))
        if self.service.openconfig_system.system.ssh_server.config.timeout:
            seconds_all = int(self.service.openconfig_system.system.ssh_server.config.timeout)
            self.proplist.append(('XE_EXEC_TIMEOUT_MINUTES', str(seconds_all // 60)))
            self.proplist.append(('XE_EXEC_TIMEOUT_SECONDS', str(seconds_all % 60)))
        if self.service.openconfig_system.system.logging.console.selectors.selector:
            for i in self.service.openconfig_system.system.logging.console.selectors.selector:
                self.proplist.append(('XE_CONSOLE_FACILITY', str(i.facility).lower().replace('oc-log:', '')))
                self.proplist.append(('XE_CONSOLE_SEVERITY', str(i.severity).lower()))
                break
        if self.service.openconfig_system.system.logging.remote_servers.remote_server:
            need_remote_facility = True
            need_remote_severity = True
            need_source_address = True
            for n in self.service.openconfig_system.system.logging.remote_servers.remote_server:
                for i in n.selectors.selector:
                    if need_remote_facility:
                        self.proplist.append(('XE_REMOTE_FACILITY', str(i.facility).lower().replace('oc-log:', '')))
                        need_remote_facility = False
                    if need_remote_severity:
                        self.proplist.append(('XE_REMOTE_SEVERITY', str(i.severity).lower()))
                        need_remote_severity = False
                if need_source_address and n.config.source_address:
                    ip_name_dict = self.xe_get_interface_ip_address()
                    if ip_name_dict[n.config.source_address]:
                        interface_name, interface_number = self.xe_get_interface_name_and_number(ip_name_dict,
                                                                                                 n.config.source_address)
                        self.proplist.append(('XE_LOGGING_SOURCE_INF_NAME', f'{interface_name}{interface_number}'))
                        need_source_address = False
        if self.service.openconfig_system.system.aaa.authentication.config.authentication_method:
            for i in self.service.openconfig_system.system.aaa.authentication.config.authentication_method:
                if i == 'TACACS_ALL':
                    self.proplist.append(('XE_AUTHENTICATION_TACACS', 'True'))
                elif i == 'LOCAL':
                    self.proplist.append(('XE_AUTHENTICATION_LOCAL', 'True'))
        if self.service.openconfig_system.system.aaa.authorization.config.authorization_method:
            for i in self.service.openconfig_system.system.aaa.authorization.config.authorization_method:
                if i == 'TACACS_ALL':
                    self.proplist.append(('XE_AUTHORIZATION_TACACS', 'True'))
                elif i == 'LOCAL':
                    self.proplist.append(('XE_AUTHORIZATION_LOCAL', 'True'))
        if self.service.openconfig_system.system.aaa.authorization.events.event:
            for i in self.service.openconfig_system.system.aaa.authorization.events.event:
                if i.event_type == 'oc-aaa-types:AAA_AUTHORIZATION_EVENT_CONFIG':
                    self.proplist.append(('XE_AUTHORIZATION_AAA_AUTHORIZATION_EVENT_CONFIG', 'True'))
                if i.event_type == 'oc-aaa-types:AAA_AUTHORIZATION_EVENT_COMMAND':
                    self.proplist.append(('XE_AUTHORIZATION_AAA_AUTHORIZATION_EVENT_COMMAND', 'True'))
        for i in self.service.openconfig_system.system.aaa.server_groups.server_group:
            for n in i.servers.server:
                if n.tacacs.config.source_address:
                    ip_name_dict = self.xe_get_interface_ip_address()
                    if ip_name_dict[n.tacacs.config.source_address]:
                        interface_name, interface_number = self.xe_get_interface_name_and_number(ip_name_dict,
                                                                                                 n.tacacs.config.source_address)
                        self.proplist.append(('XE_TACACS_SOURCE_INF_TYPE', interface_name))
                        self.proplist.append(('XE_TACACS_SOURCE_INF_NUMBER', interface_number))

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

    def xe_get_interface_ip_address(self) -> dict:
        """
        Returns a dictionary of
        IPs and interface names, e.g. {'172.16.255.1: 'Loopback0', '192.168.1.1': 'GigabitEthernet1'}
        """
        ip_name_dict = dict()
        device_config = self.root.devices.device[self.service.name].config
        for a in dir(device_config.ios__interface):
            if not a.startswith('__'):
                class_method = getattr(device_config.ios__interface, a)
                for i in class_method:
                    try:
                        if i.ip.address.primary.address:
                            ip_name_dict[str(i.ip.address.primary.address)] = str(i) + str(i.name)
                    except:
                        pass
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
