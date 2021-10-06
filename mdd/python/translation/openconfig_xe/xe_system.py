# -*- mode: python; python-indent: 4 -*-
import re
from typing import Tuple

from translation.openconfig_xe.common import xe_system_get_interface_ip_address

xe_system_initial_vars = dict(XE_TIMEZONE='',
                              XE_TIMEZONE_OFFSET_HOURS='',
                              XE_TIMEZONE_OFFSET_MINUTES='',
                              XE_NTP_SOURCE_INF_TYPE='',
                              XE_NTP_SOURCE_INF_NUMBER='',
                              XE_EXEC_TIMEOUT_MINUTES='',
                              XE_EXEC_TIMEOUT_SECONDS='',
                              XE_CONSOLE_EXEC_TIMEOUT_MINUTES='',
                              XE_CONSOLE_EXEC_TIMEOUT_SECONDS='',
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
                              XE_SSH_SOURCE_INF_TYPE='',
                              XE_SSH_SOURCE_INF_NUMBER='')


def xe_system_program_service(self) -> None:
    """
    Program service for xe NED features too complex for XML template.
    Includes:
        - aaa accounting
        - aaa server-groups
    """

    # helper functions
    def populate_accounting_events() -> None:
        for counter, m in enumerate(aaa_accounting_accounting_methods):
            if m == 'TACACS_ALL':
                method = 'tacacs+'
            else:
                method = m
            if counter == 0:
                event['group'] = method
            elif counter == 1:
                event['group2']['group'] = method
            elif counter == 2:
                event['group3']['group'] = method

    # aaa accounting
    aaa_accounting_accounting_methods = list()
    aaa_accounting_events = list()
    if self.service.oc_sys__system.aaa.accounting.config.accounting_method:
        for i in self.service.oc_sys__system.aaa.accounting.config.accounting_method:
            aaa_accounting_accounting_methods.append(i)
    if self.service.oc_sys__system.aaa.accounting.events.event:
        for i in self.service.oc_sys__system.aaa.accounting.events.event:
            aaa_accounting_events.append(
                {'config': {'event-type': i['config']['event-type'], 'record': i['config']['record']},
                 'event-type': i['event-type']})
    if aaa_accounting_accounting_methods and aaa_accounting_events:
        for e in aaa_accounting_events:
            if e['event-type'] == 'oc-aaa-types:AAA_ACCOUNTING_EVENT_COMMAND':
                if self.root.devices.device[self.device_name].config.ios__aaa.accounting.commands.exists(
                        ('15', 'default')):
                    event = self.root.devices.device[self.device_name].config.ios__aaa.accounting.commands[
                        ('15', 'default')]
                else:
                    event = self.root.devices.device[self.device_name].config.ios__aaa.accounting.commands.create(
                        ('15', 'default'))

                if e['config']['record'] == 'STOP':
                    event.action_type = 'stop-only'
                elif e['config']['record'] == 'START_STOP':
                    event.action_type = 'start-stop'

                populate_accounting_events()

            if e['event-type'] == 'oc-aaa-types:AAA_ACCOUNTING_EVENT_LOGIN':
                if self.root.devices.device[self.device_name].config.ios__aaa.accounting.exec.exists(('default')):
                    event = self.root.devices.device[self.device_name].config.ios__aaa.accounting.exec[('default')]
                else:
                    event = self.root.devices.device[self.device_name].config.ios__aaa.accounting.exec.create(
                        ('default'))

                if e['config']['record'] == 'STOP':
                    event.action_type = 'stop-only'
                elif e['config']['record'] == 'START_STOP':
                    event.action_type = 'start-stop'

                populate_accounting_events()

    # aaa server-groups
    if self.service.oc_sys__system.aaa.server_groups.server_group:
        server_groups = list()
        for group in self.service.oc_sys__system.aaa.server_groups.server_group:
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
        for g in server_groups:
            source_address = ''
            for s in g['servers']:
                if self.root.devices.device[self.device_name].config.ios__tacacs.server.exists((s.get('name'))):
                    server = self.root.devices.device[self.device_name].config.ios__tacacs.server[(s.get('name'))]
                else:
                    server = self.root.devices.device[self.device_name].config.ios__tacacs.server.create(
                        s.get('name'))

                if s.get('address'):
                    server.address.ipv4 = s.get('address')
                server.key.type = '0'
                if s.get('secret_key'):
                    server.key.secret = s.get('secret_key')
                if server.timeout:
                    server.timeout = s.get('timeout')
                if s.get('port'):
                    server.port = s.get('port')
                if s.get('source_address'):
                    source_address = s.get('source_address')

            if self.root.devices.device[self.device_name].config.ios__aaa.group.server.tacacs_plus.exists(
                    (g.get('name'))):
                group = self.root.devices.device[self.device_name].config.ios__aaa.group.server.tacacs_plus[
                    (g.get('name'))]
            else:
                group = self.root.devices.device[self.device_name].config.ios__aaa.group.server.tacacs_plus.create(
                    (g.get('name')))

            for s in g['servers']:
                if not group.server.name.exists(s.get('name')):
                    group.server.name.create(s.get('name'))
            if source_address:
                ip_name_dict = xe_system_get_interface_ip_address(self)
                if ip_name_dict[source_address]:
                    interface_name, interface_number = xe_system_get_interface_type_and_number(
                        ip_name_dict.get(source_address))
                    setattr(group.ip.tacacs.source_interface, interface_name, interface_number)


def xe_system_transform_vars(self) -> None:
    """
    Transforms values into appropriate format IOS XE template values.
    """

    if self.service.oc_sys__system.clock.config.timezone_name:
        tz = self.service.oc_sys__system.clock.config.timezone_name.split()
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
    if self.service.oc_sys__system.config.console_exec_timeout_seconds:
        seconds_all = int(self.service.oc_sys__system.config.console_exec_timeout_seconds)
        self.proplist.append(('XE_CONSOLE_EXEC_TIMEOUT_MINUTES', str(seconds_all // 60)))
        self.proplist.append(('XE_CONSOLE_EXEC_TIMEOUT_SECONDS', str(seconds_all % 60)))
    if self.service.oc_sys__system.ntp.config.ntp_source_address:
        ip_name_dict = xe_system_get_interface_ip_address(self)
        if ip_name_dict[self.service.oc_sys__system.ntp.config.ntp_source_address]:
            interface_name, interface_number = xe_system_get_interface_type_and_number(
                ip_name_dict.get(self.service.oc_sys__system.ntp.config.ntp_source_address))
            self.proplist.append(('XE_NTP_SOURCE_INF_TYPE', interface_name))
            self.proplist.append(('XE_NTP_SOURCE_INF_NUMBER', interface_number))

    if self.service.oc_sys__system.ssh_server.config.ssh_source_interface:
        interface_name, interface_number = xe_system_get_interface_type_and_number(
            self.service.oc_sys__system.ssh_server.config.ssh_source_interface)
        self.proplist.append(('XE_SSH_SOURCE_INF_TYPE', interface_name))
        self.proplist.append(('XE_SSH_SOURCE_INF_NUMBER', interface_number))

    if self.service.oc_sys__system.ssh_server.config.timeout:
        seconds_all = int(self.service.oc_sys__system.ssh_server.config.timeout)
        self.proplist.append(('XE_EXEC_TIMEOUT_MINUTES', str(seconds_all // 60)))
        self.proplist.append(('XE_EXEC_TIMEOUT_SECONDS', str(seconds_all % 60)))
    if self.service.oc_sys__system.logging.console.selectors.selector:
        for i in self.service.oc_sys__system.logging.console.selectors.selector:
            self.proplist.append(('XE_CONSOLE_FACILITY', str(i.facility).lower().replace('oc-log:', '')))
            self.proplist.append(('XE_CONSOLE_SEVERITY', str(i.severity).lower()))
            break
    if self.service.oc_sys__system.logging.remote_servers.remote_server:
        need_remote_facility = True
        need_remote_severity = True
        need_source_address = True
        for n in self.service.oc_sys__system.logging.remote_servers.remote_server:
            for i in n.selectors.selector:
                if need_remote_facility:
                    self.proplist.append(('XE_REMOTE_FACILITY', str(i.facility).lower().replace('oc-log:', '')))
                    need_remote_facility = False
                if need_remote_severity:
                    self.proplist.append(('XE_REMOTE_SEVERITY', str(i.severity).lower()))
                    need_remote_severity = False
            if need_source_address and n.config.source_address:
                ip_name_dict = xe_system_get_interface_ip_address(self)
                if ip_name_dict[n.config.source_address]:
                    interface_type, interface_number = xe_system_get_interface_type_and_number(
                        ip_name_dict.get(n.config.source_address))
                    self.proplist.append(('XE_LOGGING_SOURCE_INF_NAME', f'{interface_type}{interface_number}'))
                    need_source_address = False
    if self.service.oc_sys__system.aaa.authentication.config.authentication_method:
        for i in self.service.oc_sys__system.aaa.authentication.config.authentication_method:
            if i == 'TACACS_ALL':
                self.proplist.append(('XE_AUTHENTICATION_TACACS', 'True'))
            elif i == 'LOCAL':
                self.proplist.append(('XE_AUTHENTICATION_LOCAL', 'True'))
    if self.service.oc_sys__system.aaa.authorization.config.authorization_method:
        for i in self.service.oc_sys__system.aaa.authorization.config.authorization_method:
            if i == 'TACACS_ALL':
                self.proplist.append(('XE_AUTHORIZATION_TACACS', 'True'))
            elif i == 'LOCAL':
                self.proplist.append(('XE_AUTHORIZATION_LOCAL', 'True'))
    if self.service.oc_sys__system.aaa.authorization.events.event:
        for i in self.service.oc_sys__system.aaa.authorization.events.event:
            if i.event_type == 'oc-aaa-types:AAA_AUTHORIZATION_EVENT_CONFIG':
                self.proplist.append(('XE_AUTHORIZATION_AAA_AUTHORIZATION_EVENT_CONFIG', 'True'))
            if i.event_type == 'oc-aaa-types:AAA_AUTHORIZATION_EVENT_COMMAND':
                self.proplist.append(('XE_AUTHORIZATION_AAA_AUTHORIZATION_EVENT_COMMAND', 'True'))
    for i in self.service.oc_sys__system.aaa.server_groups.server_group:
        for n in i.servers.server:
            if n.tacacs.config.source_address:
                ip_name_dict = xe_system_get_interface_ip_address(self)
                if ip_name_dict[n.tacacs.config.source_address]:
                    interface_type, interface_number = xe_system_get_interface_type_and_number(
                        ip_name_dict.get(n.tacacs.config.source_address))
                    self.proplist.append(('XE_TACACS_SOURCE_INF_TYPE', interface_type))
                    self.proplist.append(('XE_TACACS_SOURCE_INF_NUMBER', interface_number))


def xe_system_get_interface_type_and_number(interface: str) -> Tuple[str, str]:
    """
    Receive full interface name. Returns interface type and number.
    :param interface: full interface name
    :return: tuple of interface type, interface number
    """
    rt = re.search(r'\D+', interface)
    interface_name = rt.group(0)
    rn = re.search(r'[0-9]+(\/[0-9]+)*', interface)
    interface_number = rn.group(0)
    return interface_name, interface_number
