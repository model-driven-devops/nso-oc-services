# -*- mode: python; python-indent: 4 -*-
from translation.openconfig_xe.common import xe_system_get_interface_ip_address
from translation.openconfig_xe.common import xe_get_interface_type_and_number

severity_levels_oc_to_xe = {'EMERGENCY': 'emergencies',
                            'ALERT': 'alerts',
                            'CRITICAL': 'critical',
                            'ERROR': 'errors',
                            'WARNING': 'warnings',
                            'NOTICE': 'notifications',
                            'INFORMATIONAL': 'informational',
                            'DEBUG': 'debugging'}

facility_levels_oc_to_xe = {'KERNAL': 'kern',
                            'USER': 'user',
                            'MAIL': 'mail',
                            'SYSTEM_DAEMON': 'daemon',
                            'AUTH': 'auth',
                            'SYSLOG': 'syslog',
                            'LOCAL0': 'local0',
                            'LOCAL1': 'local1',
                            'LOCAL2': 'local2',
                            'LOCAL3': 'local3',
                            'LOCAL4': 'local4',
                            'LOCAL5': 'local5',
                            'LOCAL6': 'local6',
                            'LOCAL7': 'local7'}

def xe_system_program_service(self) -> None:
    """
    Program service
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

    def xe_configure_authorization_method() -> None:
        for i in self.service.oc_sys__system.aaa.authorization.config.authorization_method:
            if i == 'TACACS_ALL':
                if not authorization_method_cdb.tacacsplus.exists():
                    authorization_method_cdb.tacacsplus.create()
            elif i == 'LOCAL':
                if not authorization_method_cdb.local.exists():
                    authorization_method_cdb.local.create()
            else:
                raise ValueError('XE aaa authorization must be TACACS_ALL or LOCAL')

    device_cdb = self.root.devices.device[self.device_name].config
    # Services
    # service finger
    if self.service.oc_sys__system.services.finger:
        if not device_cdb.ios__ip.finger.exists():
            device_cdb.ios__ip.finger.create()
    elif self.service.oc_sys__system.services.finger is False:
        if device_cdb.ios__ip.finger.exists():
            device_cdb.ios__ip.finger.delete()
    # ip gratuitous arps
    if self.service.oc_sys__system.services.ip_gratuitous_arps:
        device_cdb.ios__ip.gratuitous_arps_conf.gratuitous_arps = True
    elif self.service.oc_sys__system.services.ip_gratuitous_arps is False:
        device_cdb.ios__ip.gratuitous_arps_conf.gratuitous_arps = None
    # service password-encryption
    if self.service.oc_sys__system.services.service_password_encryption:
        device_cdb.ios__service.password_encryption.create()
    elif self.service.oc_sys__system.services.service_password_encryption is False:
        if device_cdb.ios__service.password_encryption.exists():
            device_cdb.ios__service.password_encryption.delete()
    # service-tcp-small-servers
    if self.service.oc_sys__system.services.service_tcp_small_servers:
        device_cdb.ios__service.tcp_small_servers.create()
    elif self.service.oc_sys__system.services.service_tcp_small_servers is False:
        if device_cdb.ios__service.tcp_small_servers.exists():
            device_cdb.ios__service.tcp_small_servers.delete()
    # service-udp-small-servers
    if self.service.oc_sys__system.services.service_udp_small_servers:
        device_cdb.ios__service.udp_small_servers.create()
    elif self.service.oc_sys__system.services.service_udp_small_servers is False:
        if device_cdb.ios__service.udp_small_servers.exists():
            device_cdb.ios__service.udp_small_servers.delete()
    # service http
    if self.service.oc_sys__system.services.http.http_enabled:
        device_cdb.ios__ip.http.server = True
    elif self.service.oc_sys__system.services.http.http_enabled is False:
        device_cdb.ios__ip.http.server = False
    if self.service.oc_sys__system.services.http.https_enabled:
        device_cdb.ios__ip.http.secure_server = True
    elif self.service.oc_sys__system.services.http.https_enabled is False:
        device_cdb.ios__ip.http.secure_server = False
    if self.service.oc_sys__system.services.http.ip_http_max_connections:
        device_cdb.ios__ip.http.max_connections = self.service.oc_sys__system.services.http.ip_http_max_connections
    if self.service.oc_sys__system.services.http.ip_http_secure_ciphersuite:
        for suite in self.service.oc_sys__system.services.http.ip_http_secure_ciphersuite:
            device_cdb.ios__ip.http.secure_ciphersuite.create(suite.replace('oc-system-ext:', ''))
    if self.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.connection and self.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.life and self.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.requests:
        device_cdb.ios__ip.http.timeout_policy.idle = self.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.connection
        device_cdb.ios__ip.http.timeout_policy.life = self.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.life
        device_cdb.ios__ip.http.timeout_policy.requests = self.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.requests
    # clock
    if self.service.oc_sys__system.clock.config.timezone_name:
        name, hours, minutes = xe_convert_timezone_string(self.service.oc_sys__system.clock.config.timezone_name)
        device_cdb.ios__clock.timezone.zone = name
        device_cdb.ios__clock.timezone.hours = hours
        device_cdb.ios__clock.timezone.minutes = minutes
    # config
    if self.service.oc_sys__system.config.domain_name:
        device_cdb.ios__ip.domain.name = self.service.oc_sys__system.config.domain_name
    if self.service.oc_sys__system.config.hostname:
        device_cdb.hostname = self.service.oc_sys__system.config.hostname
    if self.service.oc_sys__system.config.login_banner:
        device_cdb.banner.login = self.service.oc_sys__system.config.login_banner
    if self.service.oc_sys__system.config.motd_banner:
        device_cdb.banner.motd = self.service.oc_sys__system.config.motd_banner
    if self.service.oc_sys__system.config.enable_secret:
        device_cdb.enable.secret.secret = self.service.oc_sys__system.config.enable_secret
        device_cdb.enable.secret.type = 0
    if self.service.oc_sys__system.config.console_exec_timeout_seconds:
        seconds_all = int(self.service.oc_sys__system.config.console_exec_timeout_seconds)
        device_cdb.ios__line.console[0].exec_timeout.minutes = str(seconds_all // 60)
        device_cdb.ios__line.console[0].exec_timeout.seconds = str(seconds_all % 60)
    if self.service.oc_sys__system.config.timestamps.logging.enabled and (
            self.service.oc_sys__system.config.timestamps.logging.datetime or self.service.oc_sys__system.config.timestamps.logging.uptime):
        if self.service.oc_sys__system.config.timestamps.logging.datetime:
            dt = device_cdb.ios__service.timestamps.log.datetime.create()
            if self.service.oc_sys__system.config.timestamps.logging.localtime:
                dt.localtime.create()
        else:
            device_cdb.ios__service.timestamps.log.uptime.create()
    elif self.service.oc_sys__system.config.timestamps.logging.datetime and self.service.oc_sys__system.config.timestamps.logging.uptime:
        raise ValueError('Can not use timestamp logging with both uptime and datetime')
    elif self.service.oc_sys__system.config.timestamps.logging.enabled and (
            not self.service.oc_sys__system.config.timestamps.logging.datetime or not self.service.oc_sys__system.config.timestamps.logging.uptime):
        raise ValueError('Logging timestamps must use datetime or uptime')
    if self.service.oc_sys__system.config.timestamps.debugging.enabled and (
            self.service.oc_sys__system.config.timestamps.debugging.datetime or self.service.oc_sys__system.config.timestamps.debugging.uptime):
        if self.service.oc_sys__system.config.timestamps.debugging.datetime:
            dt = device_cdb.ios__service.timestamps.debug.datetime.create()
            if self.service.oc_sys__system.config.timestamps.debugging.localtime:
                dt.localtime.create()
        else:
            device_cdb.ios__service.timestamps.debug.uptime.create()
    elif self.service.oc_sys__system.config.timestamps.debugging.datetime and self.service.oc_sys__system.config.timestamps.debugging.uptime:
        raise ValueError('Can not use timestamp debugging with both uptime and datetime')
    elif self.service.oc_sys__system.config.timestamps.debugging.enabled and (
            not self.service.oc_sys__system.config.timestamps.debugging.datetime or not self.service.oc_sys__system.config.timestamps.debugging.uptime):
        raise ValueError('Debugging timestamps must use datetime or uptime')
    # DNS servers
    if self.service.oc_sys__system.dns:
        for service_dns_server in self.service.oc_sys__system.dns.servers.server:
            if service_dns_server.config.port != 53:
                raise ValueError('XE DNS servers must use port 53')
            if not service_dns_server.config.use_vrf or self.service.oc_netinst__network_instances.network_instance[
                service_dns_server.config.use_vrf].config.type == 'oc-ni-types:DEFAULT_INSTANCE':
                device_cdb.ios__ip.name_server.name_server_list.create(service_dns_server.address)
            elif self.service.oc_netinst__network_instances.network_instance[
                service_dns_server.config.use_vrf].config.type == 'oc-ni-types:L3VRF':
                if not device_cdb.ios__ip.name_server.vrf.exists(service_dns_server.config.use_vrf):
                    device_cdb.ios__ip.name_server.vrf.create(service_dns_server.config.use_vrf)
                device_cdb.ios__ip.name_server.vrf[service_dns_server.config.use_vrf].name_server_list.create(service_dns_server.address)
    # SSH server
    if self.service.oc_sys__system.ssh_server.config.enable:
        for service_line_vty in device_cdb.ios__line.vty:
            service_line_vty.transport.input = ['ssh']
    elif self.service.oc_sys__system.ssh_server.config.enable is False:
        for service_line_vty in device_cdb.ios__line.vty:
            if 'ssh' in service_line_vty.transport.input.as_list():
                service_line_vty.transport.input.remove('ssh')
    if self.service.oc_sys__system.ssh_server.config.protocol_version == 'V2':
        device_cdb.ios__ip.ssh.version = 2
    elif self.service.oc_sys__system.ssh_server.config.protocol_version == 'V1':
        device_cdb.ios__ip.ssh.version = 1
    elif self.service.oc_sys__system.ssh_server.config.protocol_version == 'V1_V2':
        device_cdb.ios__ip.ssh.version = None
    if self.service.oc_sys__system.ssh_server.config.rate_limit:
        raise ValueError('SSH rate-limiting is unsupported in XE')
    if self.service.oc_sys__system.ssh_server.config.session_limit:
        for service_line_vty in device_cdb.ios__line.vty:
            service_line_vty.session_limit = self.service.oc_sys__system.ssh_server.config.session_limit
    if self.service.oc_sys__system.ssh_server.config.timeout:
        seconds_all = int(self.service.oc_sys__system.ssh_server.config.timeout)
        for service_line_vty in device_cdb.ios__line.vty:
            service_line_vty.exec_timeout.minutes = str(seconds_all // 60)
            service_line_vty.exec_timeout.seconds = str(seconds_all % 60)
    if self.service.oc_sys__system.ssh_server.config.absolute_timeout_minutes:
        for service_line_vty in device_cdb.ios__line.vty:
            service_line_vty.absolute_timeout = self.service.oc_sys__system.ssh_server.config.absolute_timeout_minutes
    if self.service.oc_sys__system.ssh_server.config.ssh_timeout:
        device_cdb.ios__ip.ssh.time_out = self.service.oc_sys__system.ssh_server.config.ssh_timeout
    if self.service.oc_sys__system.ssh_server.config.ssh_source_interface:
        interface_type, interface_number = xe_get_interface_type_and_number(
            self.service.oc_sys__system.ssh_server.config.ssh_source_interface)
        device_cdb.ios__ip.ssh.source_interface[interface_type] = interface_number
    # NTP
    if self.service.oc_sys__system.ntp.config.enabled:
        if self.service.oc_sys__system.ntp.config.ntp_source_address:
            ip_name_dict = xe_system_get_interface_ip_address(self)
            if ip_name_dict[self.service.oc_sys__system.ntp.config.ntp_source_address]:
                interface_type, interface_number = xe_get_interface_type_and_number(
                    ip_name_dict.get(self.service.oc_sys__system.ntp.config.ntp_source_address))
                device_cdb.ios__ntp.source[interface_type] = interface_number
        if self.service.oc_sys__system.ntp.config.enable_ntp_auth:
            device_cdb.ios__ntp.authenticate.create()
        elif self.service.oc_sys__system.ntp.config.enable_ntp_auth is False:
            if device_cdb.ios__ntp.authenticate.exists():
                device_cdb.ios__ntp.authenticate.delete()
        if self.service.oc_sys__system.ntp.config.ntp_enable_logging:
            device_cdb.ios__ntp.logging.create()
        elif self.service.oc_sys__system.ntp.config.ntp_enable_logging is False:
            if device_cdb.ios__ntp.logging.exists():
                device_cdb.ios__ntp.logging.delete()
        if self.service.oc_sys__system.ntp.ntp_keys.ntp_key:
            for service_ntp_key in self.service.oc_sys__system.ntp.ntp_keys.ntp_key:
                self.log.info(f"service_ntp_key.config.key_type {service_ntp_key.config.key_type}")
                if service_ntp_key.config.key_type == 'oc-sys:NTP_AUTH_MD5':
                    key = device_cdb.ios__ntp.authentication_key.create(service_ntp_key.config.key_id)
                    key.md5.secret = service_ntp_key.config.key_value
                    device_cdb.ios__ntp.trusted_key.create(service_ntp_key.config.key_id)
                else:
                    raise ValueError('XE NTP must use MD5 authentication and use NTP key type NTP_AUTH_MD5.')
        if self.service.oc_sys__system.ntp.servers.server:
            for service_ntp_server in self.service.oc_sys__system.ntp.servers.server:
                if service_ntp_server.config.ntp_use_vrf:
                    if self.service.oc_netinst__network_instances.network_instance[
                        service_ntp_server.config.ntp_use_vrf].config.type == 'oc-ni-types:L3VRF':
                        if service_ntp_server.config.association_type == 'SERVER':
                            if not device_cdb.ios__ntp.server.vrf.exists(service_ntp_server.config.ntp_use_vrf):
                                device_cdb.ios__ntp.server.vrf.create(service_ntp_server.config.ntp_use_vrf)
                            device_cdb_server_vrf = device_cdb.ios__ntp.server.vrf[
                                service_ntp_server.config.ntp_use_vrf]
                            if not device_cdb_server_vrf.peer_list.exists(service_ntp_server.config.address):
                                device_cdb_server_vrf.peer_list.create(service_ntp_server.config.address)
                            if service_ntp_server.config.ntp_source_address:
                                raise ValueError('XE does not support source address to VRF NTP peers')
                            peer_cdb = device_cdb_server_vrf.peer_list[service_ntp_server.config.address]
                            xe_configure_ntp_server(service_ntp_server, peer_cdb)
                        elif service_ntp_server.config.association_type == 'PEER':
                            if not device_cdb.ios__ntp.peer.vrf.exists(service_ntp_server.config.ntp_use_vrf):
                                device_cdb.ios__ntp.peer.vrf.create(service_ntp_server.config.ntp_use_vrf)
                            device_cdb_peer_vrf = device_cdb.ios__ntp.peer.vrf[service_ntp_server.config.ntp_use_vrf]
                            if not device_cdb_peer_vrf.peer_list.exists(service_ntp_server.config.address):
                                device_cdb_peer_vrf.peer_list.create(service_ntp_server.config.address)
                            if service_ntp_server.config.ntp_source_address:
                                raise ValueError('XE does not support source address to VRF NTP peers')
                            peer_cdb = device_cdb_peer_vrf.peer_list[service_ntp_server.config.address]
                            xe_configure_ntp_server(service_ntp_server, peer_cdb)
                        else:
                            raise ValueError('XE supports ntp association types of SERVER and PEER')
                    elif self.service.oc_netinst__network_instances.network_instance[
                        service_ntp_server.config.ntp_use_vrf].config.type == 'oc-ni-types:DEFAULT_INSTANCE':
                        if service_ntp_server.config.association_type == 'SERVER':
                            if not device_cdb.ios__ntp.server.peer_list.exists(service_ntp_server.config.address):
                                device_cdb.ios__ntp.server.peer_list.create(service_ntp_server.config.address)
                            peer_cdb = device_cdb.ios__ntp.server.peer_list[service_ntp_server.config.address]
                            if service_ntp_server.config.ntp_source_address:
                                xe_configure_ntp_server_source_address(self, service_ntp_server, peer_cdb)
                            xe_configure_ntp_server(service_ntp_server, peer_cdb)
                        elif service_ntp_server.config.association_type == 'PEER':
                            if not device_cdb.ios__ntp.peer.peer_list.exists(service_ntp_server.config.address):
                                device_cdb.ios__ntp.peer.peer_list.create(service_ntp_server.config.address)
                            peer_cdb = device_cdb.ios__ntp.peer.peer_list[service_ntp_server.config.address]
                            if service_ntp_server.config.ntp_source_address:
                                xe_configure_ntp_server_source_address(self, service_ntp_server, peer_cdb)
                            xe_configure_ntp_server(service_ntp_server, peer_cdb)
                        else:
                            raise ValueError('XE supports ntp association types of SERVER and PEER')
                    else:
                        raise ValueError(
                            'XE supports ntp association association in network instances oc-ni-types:DEFAULT_INSTANCE and oc-ni-types:L3VRF')
                else:
                    if service_ntp_server.config.association_type == 'SERVER':
                        if not device_cdb.ios__ntp.server.peer_list.exists(service_ntp_server.config.address):
                            device_cdb.ios__ntp.server.peer_list.create(service_ntp_server.config.address)
                        peer_cdb = device_cdb.ios__ntp.server.peer_list[service_ntp_server.config.address]
                        if service_ntp_server.config.ntp_source_address:
                            xe_configure_ntp_server_source_address(self, service_ntp_server, peer_cdb)
                        xe_configure_ntp_server(service_ntp_server, peer_cdb)
                    elif service_ntp_server.config.association_type == 'PEER':
                        if not device_cdb.ios__ntp.peer.peer_list.exists(service_ntp_server.config.address):
                            device_cdb.ios__ntp.peer.peer_list.create(service_ntp_server.config.address)
                        peer_cdb = device_cdb.ios__ntp.peer.peer_list[service_ntp_server.config.address]
                        if service_ntp_server.config.ntp_source_address:
                            xe_configure_ntp_server_source_address(self, service_ntp_server, peer_cdb)
                        xe_configure_ntp_server(service_ntp_server, peer_cdb)
                    else:
                        raise ValueError('XE supports ntp association types of SERVER and PEER')

    elif self.service.oc_sys__system.ntp.config.enabled is False:
        if len(device_cdb.ios__ntp.server.peer_list) > 0:
            device_cdb.ios__ntp.server.peer_list.delete()
        if len(device_cdb.ios__ntp.peer.peer_list) > 0:
            device_cdb.ios__ntp.peer.peer_list.delete()
        if len(device_cdb.ios__ntp.server.vrf) > 0:
            device_cdb.ios__ntp.server.vrf.delete()
        if len(device_cdb.ios__ntp.peer.vrf) > 0:
            device_cdb.ios__ntp.peer.vrf.delete()
    # Logging
    logging_facility = set()
    remote_server_severity = list()
    if self.service.oc_sys__system.logging.console.selectors.selector:
        if len(self.service.oc_sys__system.logging.console.selectors.selector) == 1:
            key0 = self.service.oc_sys__system.logging.console.selectors.selector.keys()[0]
            device_cdb.ios__logging.console.severity_level = severity_levels_oc_to_xe.get(
                str(self.service.oc_sys__system.logging.console.selectors.selector[key0].severity))
            logging_facility.add(str(self.service.oc_sys__system.logging.console.selectors.selector[key0].facility))
        else:
            raise ValueError('XE supports 1 console logging selector.')
    if self.service.oc_sys__system.logging.terminal_monitor.selectors.selector:
        if len(self.service.oc_sys__system.logging.terminal_monitor.selectors.selector) == 1:
            key0 = self.service.oc_sys__system.logging.terminal_monitor.selectors.selector.keys()[0]
            device_cdb.ios__logging.monitor.severity_level = severity_levels_oc_to_xe.get(
                str(self.service.oc_sys__system.logging.terminal_monitor.selectors.selector[key0].severity))
            logging_facility.add(
                str(self.service.oc_sys__system.logging.terminal_monitor.selectors.selector[key0].facility))
        else:
            raise ValueError('XE supports 1 terminal-monitor logging selector.')

    if self.service.oc_sys__system.logging.remote_servers.remote_server:
        for service_remote_server in self.service.oc_sys__system.logging.remote_servers.remote_server:
            if len(service_remote_server.selectors.selector) == 1:
                key0 = service_remote_server.selectors.selector.keys()[0]
                device_cdb.ios__logging.trap = severity_levels_oc_to_xe.get(
                    str(service_remote_server.selectors.selector[key0].severity))
                remote_server_severity.append(str(service_remote_server.selectors.selector[key0].severity))
                logging_facility.add(
                    str(service_remote_server.selectors.selector[key0].facility))
            else:
                raise ValueError('XE supports 1 remote-server logging selector.')

            if service_remote_server.config.remote_port:
                if service_remote_server.config.remote_port != 514:
                    raise ValueError('XE only supports logging to port 514')

            # if service_remote_server.config.use_vrf:
            if not service_remote_server.config.use_vrf or self.service.oc_netinst__network_instances.network_instance[
                service_remote_server.config.use_vrf].config.type == 'oc-ni-types:DEFAULT_INSTANCE':
                device_cdb.ios__logging.host.ipv4.create(service_remote_server.config.host)
                if service_remote_server.config.source_address:
                    ip_name_dict = xe_system_get_interface_ip_address(self)
                    if ip_name_dict.get(service_remote_server.config.source_address):
                        interface_type, interface_number = xe_get_interface_type_and_number(
                            ip_name_dict.get(service_remote_server.config.source_address))
                        device_cdb.ios__logging.source_interface.create(f"{interface_type}{interface_number}")
            elif self.service.oc_netinst__network_instances.network_instance[
                service_remote_server.config.use_vrf].config.type == 'oc-ni-types:L3VRF':
                device_cdb.ios__logging.host.ipv4_vrf.create((service_remote_server.config.host, service_remote_server.config.use_vrf))
                if service_remote_server.config.source_address:
                    ip_name_dict = xe_system_get_interface_ip_address(self)
                    if ip_name_dict.get(service_remote_server.config.source_address):
                        interface_type, interface_number = xe_get_interface_type_and_number(
                            ip_name_dict.get(service_remote_server.config.source_address))
                        source_interface = device_cdb.ios__logging.source_interface.create(f"{interface_type}{interface_number}")
                        source_interface.vrf = service_remote_server.config.use_vrf

        if len(set(remote_server_severity)) != 1:
            raise ValueError('XE logging remote-server severity must be the same value')

    if len(logging_facility) == 1:
        device_cdb.ios__logging.facility = facility_levels_oc_to_xe.get(list(logging_facility)[0].replace('oc-log:', ''))
    elif len(logging_facility) > 1:
        raise ValueError('XE logging facility must be the same value for console, terminal-monitor, and remote-servers.')
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
                if not device_cdb.ios__tacacs.server.exists((s.get('name'))):
                    device_cdb.ios__tacacs.server.create(s.get('name'))
                server = device_cdb.ios__tacacs.server[(s.get('name'))]

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

            if not device_cdb.ios__aaa.group.server.tacacs_plus.exists(
                    (g.get('name'))):
                device_cdb.ios__aaa.group.server.tacacs_plus.create(
                    (g.get('name')))
            group = device_cdb.ios__aaa.group.server.tacacs_plus[(g.get('name'))]

            for s in g['servers']:
                if not group.server.name.exists(s.get('name')):
                    group.server.name.create(s.get('name'))
            if source_address:
                ip_name_dict = xe_system_get_interface_ip_address(self)
                if ip_name_dict[source_address]:
                    interface_name, interface_number = xe_get_interface_type_and_number(
                        ip_name_dict.get(source_address))
                    setattr(group.ip.tacacs.source_interface, interface_name, interface_number)
    # aaa authentication
    if self.service.oc_sys__system.aaa.authentication.admin_user.config.admin_password:
        if not device_cdb.username.exists('admin'):
            device_cdb.username.create('admin')
        admin_user = device_cdb.username['admin']
        admin_user.privilege = 15
        admin_user.secret.secret = self.service.oc_sys__system.aaa.authentication.admin_user.config.admin_password
        admin_user.secret.type = 0
        admin_user.password.secret = None
        admin_user.password.type = None
    if self.service.oc_sys__system.aaa.authentication.config.authentication_method:
        if not device_cdb.ios__aaa.new_model.exists():
            device_cdb.ios__aaa.new_model.create()
        if not device_cdb.ios__aaa.authentication.login.exists('default'):
            device_cdb.ios__aaa.authentication.login.create('default')
        aaa_login = device_cdb.ios__aaa.authentication.login['default']
        for i in self.service.oc_sys__system.aaa.authentication.config.authentication_method:
            if i == 'TACACS_ALL':
                aaa_login.tacacsplus.create()
            if i == 'LOCAL':
                aaa_login.local.create()
    if self.service.oc_sys__system.aaa.authentication.users.user:
        for service_user in self.service.oc_sys__system.aaa.authentication.users.user:
            if not device_cdb.username.exists(service_user.username):
                device_cdb.username.create(service_user.username)
            user_cdb = device_cdb.username[service_user.username]
            if service_user.config.password:
                user_cdb.secret.secret = service_user.config.password
                user_cdb.secret.type = 0
                user_cdb.password.secret = None
                user_cdb.password.type = None
            self.log.info(f"service_user.config.role  {service_user.config.role}")
            if service_user.config.role == 'SYSTEM_ROLE_ADMIN':
                user_cdb.privilege = 15
            # if service_user.config.ssh_key:  # TODO
            #     if not device_cdb.ios__ip.ssh.pubkey_chain.username.exists(service_user.username):
            #         device_cdb.ios__ip.ssh.pubkey_chain.username.create(service_user.username)
            #     ssh_user_cdb = device_cdb.ios__ip.ssh.pubkey_chain.username[service_user.username]
            #     key_cdb = ssh_user_cdb.key_hash.create('ssh-rsa')
            #     key_cdb.key_name = service_user.config.ssh_key
    # aaa authorization
    if self.service.oc_sys__system.aaa.authorization.events.event:
        if not device_cdb.ios__aaa.new_model.exists():
            device_cdb.ios__aaa.new_model.create()
        for i in self.service.oc_sys__system.aaa.authorization.events.event:
            if i.event_type == 'oc-aaa-types:AAA_AUTHORIZATION_EVENT_CONFIG':
                if not device_cdb.ios__aaa.authorization.exec.exists('default'):
                    device_cdb.ios__aaa.authorization.exec.create('default')
                authorization_method_cdb = device_cdb.ios__aaa.authorization.exec['default']
                if self.service.oc_sys__system.aaa.authorization.config.authorization_method:
                    xe_configure_authorization_method()
            elif i.event_type == 'oc-aaa-types:AAA_AUTHORIZATION_EVENT_COMMAND':
                if not device_cdb.ios__aaa.authorization.config_commands:
                    device_cdb.ios__aaa.authorization.config_commands.create()
                if not device_cdb.ios__aaa.authorization.commands.exists('default'):
                    device_cdb.ios__aaa.authorization.commands.create('default')
                authorization_method_cdb = device_cdb.ios__aaa.authorization.commands['default']
                authorization_method_cdb.level = 15
                if self.service.oc_sys__system.aaa.authorization.config.authentication_method:
                    xe_configure_authorization_method()
            else:
                raise ValueError('XE aaa authorization.events.event must be oc-aaa-types:AAA_AUTHORIZATION_EVENT_CONFIG or oc-aaa-types:AAA_AUTHORIZATION_EVENT_COMMAND')
    # aaa accounting
    aaa_accounting_accounting_methods = list()
    aaa_accounting_events = list()
    if self.service.oc_sys__system.aaa.accounting.config.accounting_method:
        if not device_cdb.ios__aaa.new_model.exists():
            device_cdb.ios__aaa.new_model.create()
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
                if not device_cdb.ios__aaa.accounting.commands.exists(
                        ('15', 'default')):
                    device_cdb.ios__aaa.accounting.commands.create(
                        ('15', 'default'))
                event = device_cdb.ios__aaa.accounting.commands[
                    ('15', 'default')]
                if e['config']['record'] == 'STOP':
                    event.action_type = 'stop-only'
                elif e['config']['record'] == 'START_STOP':
                    event.action_type = 'start-stop'

                populate_accounting_events()

            if e['event-type'] == 'oc-aaa-types:AAA_ACCOUNTING_EVENT_LOGIN':
                if not device_cdb.ios__aaa.accounting.exec.exists(('default')):
                    event = device_cdb.ios__aaa.accounting.exec.create(
                        ('default'))
                event = device_cdb.ios__aaa.accounting.exec[('default')]
                if e['config']['record'] == 'STOP':
                    event.action_type = 'stop-only'
                elif e['config']['record'] == 'START_STOP':
                    event.action_type = 'start-stop'

                populate_accounting_events()


def xe_configure_ntp_server_source_address(self, service_ntp_server, peer_cdb) -> None:
    ip_name_dict = xe_system_get_interface_ip_address(self)
    if ip_name_dict.get(service_ntp_server.config.ntp_source_address):
        interface_type, interface_number = xe_get_interface_type_and_number(
            ip_name_dict.get(service_ntp_server.config.ntp_source_address))
        peer_cdb.source[interface_type] = interface_number


def xe_configure_ntp_server(service_ntp_server, peer_cdb) -> None:
    """
    Receive service and cdb_server objects and configure features
    """
    if service_ntp_server.config.ntp_auth_key_id:
        peer_cdb.key = service_ntp_server.config.ntp_auth_key_id
    if service_ntp_server.config.iburst:
        peer_cdb.iburst.create()
    elif service_ntp_server.iburst is False:
        if peer_cdb.iburst.exits():
            peer_cdb.iburst.delete()
    if service_ntp_server.config.port:
        if service_ntp_server.config.port != 123:
            raise ValueError('XE supports NTP using port 123')
    if service_ntp_server.config.prefer:
        peer_cdb.prefer.create()
    elif service_ntp_server.config.prefer is False:
        if peer_cdb.prefer.exists():
            peer_cdb.prefer.delete()
    if service_ntp_server.config.version:
        peer_cdb.version = service_ntp_server.config.version


def xe_convert_timezone_string(timezone_name: str) -> tuple:
    """
    :param timezone_name: str e.g. 'EDT -4 0'
    :return: tuple e.g. ('EDT', '-4', '0'
    """
    tz = timezone_name.split()
    if len(tz) != 3:
        raise ValueError
    else:
        xe_timezone = tz[0]
    if -12 > int(tz[1]) or int(tz[1]) > 12:
        raise ValueError
    else:
        xe_timezone_offset_hours = tz[1]
    if 0 > int(tz[2]) or int(tz[2]) > 60:
        raise ValueError
    else:
        xe_timezone_offset_minutes = tz[2]
    return xe_timezone, xe_timezone_offset_hours, xe_timezone_offset_minutes
