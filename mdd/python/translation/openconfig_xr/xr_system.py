# -*- mode: python; python-indent: 4 -*-

def xr_system_program_service(self, nso_props) -> None:
    """
    Program service
    """

    device_cdb = nso_props.root.devices.device[nso_props.device_name].config

    # Services
    # config
    if nso_props.service.oc_sys__system.config.domain_name:
        device_cdb.cisco_ios_xr__domain.name = nso_props.service.oc_sys__system.config.domain_name
    if nso_props.service.oc_sys__system.config.hostname:
        device_cdb.cisco_ios_xr__hostname = nso_props.service.oc_sys__system.config.hostname
    if nso_props.service.oc_sys__system.config.login_banner:
        device_cdb.cisco_ios_xr__banner.login.start_marker = '^'
        device_cdb.cisco_ios_xr__banner.login.message = nso_props.service.oc_sys__system.config.login_banner
        device_cdb.cisco_ios_xr__banner.login.end_marker = '^'
    if nso_props.service.oc_sys__system.config.motd_banner:
        device_cdb.cisco_ios_xr__banner.motd.start_marker = '^'
        device_cdb.cisco_ios_xr__banner.motd.message = nso_props.service.oc_sys__system.config.motd_banner
        device_cdb.cisco_ios_xr__banner.motd.end_marker = '^'
    if nso_props.service.oc_sys__system.config.enable_secret:
        device_cdb.cisco_ios_xr__line.default.secret.secret = nso_props.service.oc_sys__system.config.enable_secret
        device_cdb.cisco_ios_xr__line.default.secret.type = 0
    if nso_props.service.oc_sys__system.config.console_exec_timeout_seconds:
        seconds_all = int(nso_props.service.oc_sys__system.config.console_exec_timeout_seconds)
        device_cdb.cisco_ios_xr__line.console.exec_timeout.minutes = str(seconds_all // 60)
        device_cdb.cisco_ios_xr__line.console.exec_timeout.seconds = str(seconds_all % 60)
    if nso_props.service.oc_sys__system.config.ip_options:
        raise NotImplementedError('openconfig-system-config-ip-options has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.timestamps.logging.config.enabled and (
            nso_props.service.oc_sys__system.timestamps.logging.config.datetime or nso_props.service.oc_sys__system.timestamps.logging.config.uptime):
        raise NotImplementedError('openconfig-system-config-ip-options has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.timestamps.logging.config.datetime and nso_props.service.oc_sys__system.timestamps.logging.config.uptime:
        raise ValueError('Can not use timestamp logging with both uptime and datetime')
    elif nso_props.service.oc_sys__system.timestamps.logging.config.enabled and (
            not nso_props.service.oc_sys__system.timestamps.logging.config.datetime or not nso_props.service.oc_sys__system.timestamps.logging.config.uptime):
        raise ValueError('Logging timestamps must use datetime or uptime')
    if nso_props.service.oc_sys__system.timestamps.debugging.config.enabled and (
            nso_props.service.oc_sys__system.timestamps.debugging.config.datetime or nso_props.service.oc_sys__system.timestamps.debugging.config.uptime):
        raise NotImplementedError('openconfig-system-config-timestamps-debugging has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.timestamps.debugging.config.datetime and nso_props.service.oc_sys__system.timestamps.debugging.config.uptime:
        raise ValueError('Can not use timestamp debugging with both uptime and datetime')
    elif nso_props.service.oc_sys__system.timestamps.debugging.config.enabled and (
            not nso_props.service.oc_sys__system.timestamps.debugging.config.datetime or not nso_props.service.oc_sys__system.timestamps.debugging.config.uptime):
        raise ValueError('Debugging timestamps must use datetime or uptime')
    # login on-success
    if nso_props.service.oc_sys__system.services.login_security_policy.config.on_success:
        raise ValueError('login_security_policy not supported in XR')
    elif nso_props.service.oc_sys__system.services.login_security_policy.config.on_success is False:
        raise ValueError('login_security_policy not supported in XR')
    # login on-failure
    if nso_props.service.oc_sys__system.services.login_security_policy.config.on_failure:
        raise ValueError('login_security_policy not supported in XR')
    elif nso_props.service.oc_sys__system.services.login_security_policy.config.on_failure is False:
        raise ValueError('login_security_policy not supported in XR')
    # login block-for
    if nso_props.service.oc_sys__system.services.login_security_policy.block_for.config.seconds and \
            nso_props.service.oc_sys__system.services.login_security_policy.block_for.config.attempts and \
            nso_props.service.oc_sys__system.services.login_security_policy.block_for.config.within:
        raise ValueError('login_security_policy not supported in XR')
    # archive logging
    if nso_props.service.oc_sys__system.services.config.archive_logging:
        raise ValueError('archive logging not supported in XR')
    elif nso_props.service.oc_sys__system.services.config.archive_logging is False:
        raise ValueError('archive logging not supported in XR')
    # service password-encryption
    if nso_props.service.oc_sys__system.services.config.service_password_encryption:
        raise ValueError('service_password_encryption not supported in XR')
    elif nso_props.service.oc_sys__system.services.config.service_password_encryption is False:
        raise ValueError('service_password_encryption not supported in XR')
    # DNS servers
    if len(nso_props.service.oc_sys__system.dns.servers.server) > 0:
        raise NotImplementedError('openconfig-system-dns has not yet been implemented for XR')
    # SSH server
    if nso_props.service.oc_sys__system.ssh_server.config.enable:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.ssh_server.config.enable is False:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.ssh_server.config.protocol_version == 'V2':
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.ssh_server.config.protocol_version == 'V1':
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.ssh_server.config.protocol_version == 'V1_V2':
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.ssh_server.config.rate_limit:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.ssh_server.config.session_limit:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.ssh_server.config.timeout:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.ssh_server.config.absolute_timeout_minutes:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.ssh_server.config.ssh_timeout:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.ssh_server.config.ssh_source_interface:
        raise NotImplementedError('openconfig-system-ssh-server-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.ssh_server.algorithm.config.encryption:
        device_cdb.cisco_ios_xr__ssh.server.algorithms.cipher.delete()
        for enc in nso_props.service.oc_sys__system.ssh_server.algorithm.config.encryption:
            if enc == 'triple-des-cbc':
                device_cdb.cisco_ios_xr__ssh.server.algorithms.cipher.create(enc.replace('triple-des-cbc', '3des-cbc'))
            else:
                device_cdb.cisco_ios_xr__ssh.server.algorithms.cipher.create(enc)
    if nso_props.service.oc_sys__system.ssh_server.algorithm.config.mac:
        raise NotImplementedError('openconfig-system-ssh-server-algorithm-config-mac has not yet been implemented for XR')

    # boot network
    if nso_props.service.oc_sys__system.services.boot_network.config.bootnetwork_enabled == "DISABLED":
        raise ValueError('boot_network not supported in XR')
    # IP bootp server
    if nso_props.service.oc_sys__system.services.config.ip_bootp_server:
        raise ValueError('ip_bootp_server not supported in XR')
    elif nso_props.service.oc_sys__system.services.config.ip_bootp_server is False:
        raise ValueError('ip_bootp_server not supported in XR')
    # IP DNS server
    if nso_props.service.oc_sys__system.services.config.ip_dns_server:
        raise ValueError('ip_dns_server not supported in XR')
    elif nso_props.service.oc_sys__system.services.config.ip_dns_server is False:
        raise ValueError('ip_dns_server not supported in XR')
    # IP identd
    if nso_props.service.oc_sys__system.services.config.ip_identd:
        raise ValueError('ip_identd not supported in XR')
    elif nso_props.service.oc_sys__system.services.config.ip_identd is False:
        raise ValueError('ip_identd not supported in XR')
    # IP rcmd RCP enable
    if nso_props.service.oc_sys__system.services.config.ip_rcmd_rcp_enable:
        raise ValueError('ip_rcmd_rcp_enable not supported in XR')
    elif nso_props.service.oc_sys__system.services.config.ip_rcmd_rcp_enable is False:
        raise ValueError('ip_rcmd_rcp_enable not supported in XR')
    # IP rcmd RSH enable
    if nso_props.service.oc_sys__system.services.config.ip_rcmd_rsh_enable:
        raise ValueError('ip_rcmd_rsh_enable not supported in XR')
    elif nso_props.service.oc_sys__system.services.config.ip_rcmd_rsh_enable is False:
        raise ValueError('ip_rcmd_rsh_enable not supported in XR')
    # service finger
    if nso_props.service.oc_sys__system.services.config.finger:
        raise ValueError('finger not supported in XR')
    elif nso_props.service.oc_sys__system.services.config.finger is False:
        raise ValueError('finger not supported in XR')
    # service config
    if nso_props.service.oc_sys__system.services.config.service_config:
        raise ValueError('service_config not supported in XR')
    elif nso_props.service.oc_sys__system.services.config.service_config is False:
        raise ValueError('service_config not supported in XR')
    # service-tcp-small-servers
    if nso_props.service.oc_sys__system.services.config.service_tcp_small_servers:
        device_cdb.cisco_ios_xr__service.ipv4.tcp_small_servers.max_servers = 2147483647
    elif nso_props.service.oc_sys__system.services.config.service_tcp_small_servers is False:
        if device_cdb.cisco_ios_xr__service.ipv4.tcp_small_servers.max_servers and \
                device_cdb.cisco_ios_xr__service.ipv4.tcp_small_servers.max_servers > 0:
            device_cdb.cisco_ios_xr__service.ipv4.tcp_small_servers.delete()
    # service-udp-small-servers
    if nso_props.service.oc_sys__system.services.config.service_udp_small_servers:
        device_cdb.cisco_ios_xr__service.ipv4.udp_small_servers.max_servers = 2147483647
    elif nso_props.service.oc_sys__system.services.config.service_udp_small_servers is False:
        if device_cdb.cisco_ios_xr__service.ipv4.udp_small_servers.max_servers and \
                device_cdb.cisco_ios_xr__service.ipv4.udp_small_servers.max_servers > 0:
            device_cdb.cisco_ios_xr__service.ipv4.udp_small_servers.delete()
    # service pad
    if nso_props.service.oc_sys__system.services.config.service_pad:
        raise ValueError('service_pad not supported in XR')
    elif nso_props.service.oc_sys__system.services.config.service_pad is False:
        raise ValueError('service_pad not supported in XR')
    # NTP
    if nso_props.service.oc_sys__system.ntp.config.enabled:
        raise NotImplementedError('openconfig-system-ntp-config has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.ntp.config.enabled is False:
        raise NotImplementedError('openconfig-system-ntp-config has not yet been implemented for XR')
    # Logging
    if nso_props.service.oc_sys__system.logging.buffered.config.severity and nso_props.service.oc_sys__system.logging.buffered.config.buffer_size:
        raise NotImplementedError('openconfig-system-logging-buffered-config has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.logging.buffered.config.enabled is False:
        raise NotImplementedError('openconfig-system-logging-buffered-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.logging.console.config.enabled is False:
        raise NotImplementedError('openconfig-system-logging-console-config has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.logging.console.selectors.selector:
        raise NotImplementedError('openconfig-system-logging-console-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.logging.terminal_monitor.selectors.selector:
        raise NotImplementedError('openconfig-system-logging-terminal-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.logging.remote_servers.remote_server:
        raise NotImplementedError('openconfig-system-logging-remote-servers-config has not yet been implemented for XR')
    # aaa server-groups
    # gather group and server configurations
    if len(nso_props.service.oc_sys__system.aaa.server_groups.server_group) > 0:
        raise NotImplementedError('openconfig-system-aaa-server-groups has not yet been implemented for XR')
    # aaa authentication
    if nso_props.service.oc_sys__system.aaa.authentication.admin_user.config.admin_password:
        raise NotImplementedError('openconfig-system-aaa-authentication-config has not yet been implemented for XR')
    if len(nso_props.service.oc_sys__system.aaa.authentication.config.authentication_method) > 0:
        raise NotImplementedError('openconfig-system-aaa-authentication-config has not yet been implemented for XR')
    if len(nso_props.service.oc_sys__system.aaa.authentication.oc_system_ext__authentication_lists_login.config.authentication_method) > 0:
        raise NotImplementedError('openconfig-system-aaa-authentication-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.aaa.authentication.users.user:
        raise NotImplementedError('openconfig-system-aaa-authentication-config has not yet been implemented for XR')
    # aaa authorization
    if nso_props.service.oc_sys__system.aaa.authorization.events.event:
        raise NotImplementedError('openconfig-system-aaa-authorization-config has not yet been implemented for XR')
    # aaa accounting
    if nso_props.service.oc_sys__system.aaa.accounting.config.accounting_method:
        raise NotImplementedError('openconfig-system-aaa-accounting-config has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.aaa.accounting.events.event:
        raise NotImplementedError('openconfig-system-aaa-accounting-config has not yet been implemented for XR')
    # service domain lookup disable (no ip domain lookup)
    if nso_props.service.oc_sys__system.services.config.ip_domain_lookup is False:
        device_cdb.cisco_ios_xr__domain.lookup.disable.create()
    elif nso_props.service.oc_sys__system.services.config.ip_domain_lookup is True:
        if device_cdb.cisco_ios_xr__domain.lookup.disable.exists():
            device_cdb.cisco_ios_xr__domain.lookup.disable.delete()
    # service finger
    if nso_props.service.oc_sys__system.services.config.finger:
        raise NotImplementedError('openconfig-system-service-finger has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.services.config.finger is False:
        raise NotImplementedError('openconfig-system-service-finger has not yet been implemented for XR')
    # ip gratuitous arps
    if nso_props.service.oc_sys__system.services.config.ip_gratuitous_arps:
        raise NotImplementedError('openconfig-system-ip-gratuitous-arp has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.services.config.ip_gratuitous_arps is False:
        raise NotImplementedError('openconfig-system-ip-gratuitous-arp has not yet been implemented for XR')
    # service password-encryption
    if nso_props.service.oc_sys__system.services.config.service_password_encryption:
        raise NotImplementedError('openconfig-system-service-password-encryption has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.services.config.service_password_encryption is False:
        raise NotImplementedError('openconfig-system-service-password-encryption has not yet been implemented for XR')
    # service http
    if nso_props.service.oc_sys__system.services.http.config.http_enabled:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.services.http.config.http_enabled is False:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.services.http.config.https_enabled:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for XR')
    elif nso_props.service.oc_sys__system.services.http.config.https_enabled is False:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.services.http.config.ip_http_max_connections:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.services.http.config.ip_http_secure_ciphersuite:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for XR')
    if nso_props.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.connection and nso_props.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.life and nso_props.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.requests:
        raise NotImplementedError('openconfig-system-service-http has not yet been implemented for XR')
    # nat pools
    if len(nso_props.service.oc_sys__system.services.nat.pools.pool) > 0:
        raise NotImplementedError('openconfig-system-nat-pools has not yet been implemented for XR')
    # nat source inside local acl
    if len(nso_props.service.oc_sys__system.services.nat.inside.source.local_addresses_access_lists.local_addresses_access_list) > 0:
        raise NotImplementedError('openconfig-system-nat-source-inside-local-acl has not yet been implemented for XR')
    # clock
    if nso_props.service.oc_sys__system.clock.config.timezone_name:
        raise NotImplementedError('openconfig-system-clock-config has not yet been implemented for XR')
