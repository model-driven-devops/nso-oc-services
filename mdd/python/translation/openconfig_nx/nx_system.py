# -*- mode: python; python-indent: 4 -*-

def nx_system_program_service(self) -> None:
    """
    Program service
    """

    device_cdb = self.root.devices.device[self.device_name].config
    
    # Services
    # config
    if self.service.oc_sys__system.config.domain_name:
        device_cdb.ip.domain_name = self.service.oc_sys__system.config.domain_name
    # TODO Research this issue
    # For some odd reason, setting the hostname here messes up our after config copy. The result returns the following
    # "stdout": [
    #     "\u001b[5D\u001b[J"
    # ]
    # This causes our assertions to fail as the before config has only that unicode string to compare against.
    # if self.service.oc_sys__system.config.hostname:
    #     device_cdb.hostname = 'test'
    #     device_cdb.hostname = self.service.oc_sys__system.config.hostname
    if self.service.oc_sys__system.config.login_banner:
        device_cdb.banner.exec.start_marker = '^'
        device_cdb.banner.exec.message = self.service.oc_sys__system.config.login_banner
        device_cdb.banner.exec.end_marker = '^'
    if self.service.oc_sys__system.config.motd_banner:
        device_cdb.banner.motd.start_marker = '^'
        device_cdb.banner.motd.message = self.service.oc_sys__system.config.motd_banner
        device_cdb.banner.motd.end_marker = '^'
    if self.service.oc_sys__system.config.enable_secret:
        self.log.warn('There is no concept of enable-secret for NX. This will be skipped.')
    if self.service.oc_sys__system.config.console_exec_timeout_seconds:
        seconds_all = int(self.service.oc_sys__system.config.console_exec_timeout_seconds)
        # NX only stores minutes. We truncate the decimals.
        device_cdb.line.console.exec_timeout = str(int(seconds_all / 60))
    if self.service.oc_sys__system.config.ip_options:
        raise NotImplementedError('openconfig-system-config-ip-options has not yet been implemented for NX')
    if self.service.oc_sys__system.timestamps.logging.config.enabled and (
            self.service.oc_sys__system.timestamps.logging.config.datetime or self.service.oc_sys__system.timestamps.logging.config.uptime):
        raise NotImplementedError('openconfig-system-config-ip-options has not yet been implemented for NX')
    elif self.service.oc_sys__system.timestamps.logging.config.datetime and self.service.oc_sys__system.timestamps.logging.config.uptime:
        raise ValueError('Can not use timestamp logging with both uptime and datetime')
    elif self.service.oc_sys__system.timestamps.logging.config.enabled and (
            not self.service.oc_sys__system.timestamps.logging.config.datetime or not self.service.oc_sys__system.timestamps.logging.config.uptime):
        raise ValueError('Logging timestamps must use datetime or uptime')
    if self.service.oc_sys__system.timestamps.debugging.config.enabled and (
            self.service.oc_sys__system.timestamps.debugging.config.datetime or self.service.oc_sys__system.timestamps.debugging.config.uptime):
        raise NotImplementedError('openconfig-system-config-timestamps-debugging has not yet been implemented for NX')
    elif self.service.oc_sys__system.timestamps.debugging.config.datetime and self.service.oc_sys__system.timestamps.debugging.config.uptime:
        raise ValueError('Can not use timestamp debugging with both uptime and datetime')
    elif self.service.oc_sys__system.timestamps.debugging.config.enabled and (
            not self.service.oc_sys__system.timestamps.debugging.config.datetime or not self.service.oc_sys__system.timestamps.debugging.config.uptime):
        raise ValueError('Debugging timestamps must use datetime or uptime')
    # login on-success
    if self.service.oc_sys__system.services.login_security_policy.config.on_success:
        raise ValueError('login_security_policy not supported in NX')
    elif self.service.oc_sys__system.services.login_security_policy.config.on_success is False:
        raise ValueError('login_security_policy not supported in NX')
    # login on-failure
    if self.service.oc_sys__system.services.login_security_policy.config.on_failure:
        raise ValueError('login_security_policy not supported in NX')
    elif self.service.oc_sys__system.services.login_security_policy.config.on_failure is False:
        raise ValueError('login_security_policy not supported in NX')
    # login block-for
    if self.service.oc_sys__system.services.login_security_policy.block_for.config.seconds and \
            self.service.oc_sys__system.services.login_security_policy.block_for.config.attempts and \
            self.service.oc_sys__system.services.login_security_policy.block_for.config.within:
        raise ValueError('login_security_policy not supported in NX')
    # DNS servers
    if len(self.service.oc_sys__system.dns.servers.server) > 0:
        raise NotImplementedError('openconfig-system-dns has not yet been implemented for NX')
    # SSH server
    if self.service.oc_sys__system.ssh_server.config.enable:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for NX')
    elif self.service.oc_sys__system.ssh_server.config.enable is False:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for NX')
    if self.service.oc_sys__system.ssh_server.config.protocol_version == 'V2':
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for NX')
    elif self.service.oc_sys__system.ssh_server.config.protocol_version == 'V1':
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for NX')
    elif self.service.oc_sys__system.ssh_server.config.protocol_version == 'V1_V2':
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for NX')
    if self.service.oc_sys__system.ssh_server.config.rate_limit:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for NX')
    if self.service.oc_sys__system.ssh_server.config.session_limit:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for NX')
    if self.service.oc_sys__system.ssh_server.config.timeout:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for NX')
    if self.service.oc_sys__system.ssh_server.config.absolute_timeout_minutes:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for NX')
    if self.service.oc_sys__system.ssh_server.config.ssh_timeout:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for NX')
    if self.service.oc_sys__system.ssh_server.config.ssh_source_interface:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for NX')
    # NTP
    if self.service.oc_sys__system.ntp.config.enabled:
        raise NotImplementedError('openconfig-system-ntp-config has not yet been implemented for NX')
    elif self.service.oc_sys__system.ntp.config.enabled is False:
        raise NotImplementedError('openconfig-system-ntp-config has not yet been implemented for NX')
    # Logging
    if self.service.oc_sys__system.logging.buffered.config.severity and self.service.oc_sys__system.logging.buffered.config.buffer_size:
        raise NotImplementedError('openconfig-system-logging-buffered-config has not yet been implemented for NX')
    elif self.service.oc_sys__system.logging.buffered.config.enabled is False:
        raise NotImplementedError('openconfig-system-logging-buffered-config has not yet been implemented for NX')
    if self.service.oc_sys__system.logging.console.config.enabled is False:
        raise NotImplementedError('openconfig-system-logging-console-config has not yet been implemented for NX')
    elif self.service.oc_sys__system.logging.console.selectors.selector:
        raise NotImplementedError('openconfig-system-logging-console-config has not yet been implemented for NX')
    if self.service.oc_sys__system.logging.terminal_monitor.selectors.selector:
        raise NotImplementedError('openconfig-system-logging-terminal-config has not yet been implemented for NX')
    if self.service.oc_sys__system.logging.remote_servers.remote_server:
        raise NotImplementedError('openconfig-system-logging-remote-servers-config has not yet been implemented for NX')
    # aaa server-groups
    # gather group and server configurations
    if len(self.service.oc_sys__system.aaa.server_groups.server_group) > 0:
        raise NotImplementedError('openconfig-system-aaa-server-groups has not yet been implemented for NX')
    # aaa authentication
    if self.service.oc_sys__system.aaa.authentication.admin_user.config.admin_password:
        raise NotImplementedError('openconfig-system-aaa-authentication-config has not yet been implemented for NX')
    if len(self.service.oc_sys__system.aaa.authentication.config.authentication_method) > 0:
        raise NotImplementedError('openconfig-system-aaa-authentication-config has not yet been implemented for NX')
    if len(self.service.oc_sys__system.aaa.authentication.oc_system_ext__authentication_lists_login.config.authentication_method) > 0:
        raise NotImplementedError('openconfig-system-aaa-authentication-config has not yet been implemented for NX')
    if self.service.oc_sys__system.aaa.authentication.users.user:
        raise NotImplementedError('openconfig-system-aaa-authentication-config has not yet been implemented for NX')
    # aaa authorization
    if self.service.oc_sys__system.aaa.authorization.events.event:
        raise NotImplementedError('openconfig-system-aaa-authorization-config has not yet been implemented for NX')
    # aaa accounting
    if self.service.oc_sys__system.aaa.accounting.config.accounting_method:
        raise NotImplementedError('openconfig-system-aaa-accounting-config has not yet been implemented for NX')
    if self.service.oc_sys__system.aaa.accounting.events.event:
        raise NotImplementedError('openconfig-system-aaa-accounting-config has not yet been implemented for NX')
    # service domain lookup disable (no ip domain lookup)
    device_cdb.nx__ip.domain_lookup = self.service.oc_sys__system.services.config.ip_domain_lookup
    # service finger
    if self.service.oc_sys__system.services.config.finger:
        raise NotImplementedError('openconfig-system-service-finger has not yet been implemented for NX')
    elif self.service.oc_sys__system.services.config.finger is False:
        raise NotImplementedError('openconfig-system-service-finger has not yet been implemented for NX')
    # ip gratuitous arps
    if self.service.oc_sys__system.services.config.ip_gratuitous_arps:
        raise NotImplementedError('openconfig-system-ip-gratuitous-arp has not yet been implemented for NX')
    elif self.service.oc_sys__system.services.config.ip_gratuitous_arps is False:
        raise NotImplementedError('openconfig-system-ip-gratuitous-arp has not yet been implemented for NX')
    # service password-encryption
    if self.service.oc_sys__system.services.config.service_password_encryption:
        raise NotImplementedError('openconfig-system-service-password-encryption has not yet been implemented for NX')
    elif self.service.oc_sys__system.services.config.service_password_encryption is False:
        raise NotImplementedError('openconfig-system-service-password-encryption has not yet been implemented for NX')
    # service-tcp-small-servers
    if self.service.oc_sys__system.services.config.service_tcp_small_servers:
        raise NotImplementedError('openconfig-system-service-tcp-small-servers has not yet been implemented for NX')
    elif self.service.oc_sys__system.services.config.service_tcp_small_servers is False:
        raise NotImplementedError('openconfig-system-service-tcp-small-servers has not yet been implemented for NX')
    # service-udp-small-servers
    if self.service.oc_sys__system.services.config.service_udp_small_servers:
        raise NotImplementedError('openconfig-system-service-udp-small-servers has not yet been implemented for NX')
    elif self.service.oc_sys__system.services.config.service_udp_small_servers is False:
        raise NotImplementedError('openconfig-system-service-udp-small-servers has not yet been implemented for NX')
    # archive logging
    if self.service.oc_sys__system.services.config.archive_logging:
        raise ValueError('archive logging not supported in NX')
    elif self.service.oc_sys__system.services.config.archive_logging is False:
        raise ValueError('archive logging not supported in NX')
    # service http
    if self.service.oc_sys__system.services.http.config.http_enabled:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for NX')
    elif self.service.oc_sys__system.services.http.config.http_enabled is False:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for NX')
    if self.service.oc_sys__system.services.http.config.https_enabled:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for NX')
    elif self.service.oc_sys__system.services.http.config.https_enabled is False:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for NX')
    if self.service.oc_sys__system.services.http.config.ip_http_max_connections:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for NX')
    if self.service.oc_sys__system.services.http.config.ip_http_secure_ciphersuite:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for NX')
    if self.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.connection and self.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.life and self.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.requests:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for NX')
    # nat pools
    if len(self.service.oc_sys__system.services.nat.pools.pool) > 0:
        raise NotImplementedError('openconfig-system-nat-pools has not yet been implemented for NX')
    # nat source inside local acl
    if len(self.service.oc_sys__system.services.nat.inside.source.local_addresses_access_lists.local_addresses_access_list) > 0:
        raise NotImplementedError('openconfig-system-nat-source-inside-local-acl has not yet been implemented for NX')
    # clock
    if self.service.oc_sys__system.clock.config.timezone_name:
        raise NotImplementedError('openconfig-system-clock-config has not yet been implemented for NX')
