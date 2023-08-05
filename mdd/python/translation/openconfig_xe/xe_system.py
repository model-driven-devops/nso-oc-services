# -*- mode: python; python-indent: 4 -*-
from translation.openconfig_xe.common import xe_system_get_interface_ip_address
from translation.common import get_interface_type_and_number

severity_levels_oc_to_xe = {'EMERGENCY': 'emergencies',
                            'ALERT': 'alerts',
                            'CRITICAL': 'critical',
                            'ERROR': 'errors',
                            'WARNING': 'warnings',
                            'NOTICE': 'notifications',
                            'INFORMATIONAL': 'informational',
                            'DEBUG': 'debugging'}

facility_levels_oc_to_xe = {'KERNEL': 'kern',
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


def aaa_configure_methods(aaa_cdb, service_methods) -> None:
    aaa_method_options = {'TACACS_ALL': 'tacacs+',
                          'RADIUS_ALL': 'radius'}
    aaa_groups = {0: aaa_cdb,
                  1: aaa_cdb.group2,
                  2: aaa_cdb.group3}
    login_group_counter = 0
    for i in service_methods:
        if i == 'LOCAL':
            aaa_cdb.local.create()
        else:
            aaa_method = aaa_method_options.get(i, i)
            setattr(aaa_groups.get(login_group_counter), 'group', aaa_method)
            login_group_counter += 1


def xe_system_program_service(self, nso_props) -> None:
    """
    Program service
    """

    # helper functions
    def configure_local_addresses_access_list_nat() -> None:
        if service_nat_acl.config.global_pool_name:
            nat_acl_cdb.pool = service_nat_acl.config.global_pool_name
        elif service_nat_acl.config.global_interface_name:
            nat_acl_cdb.interface = service_nat_acl.config.global_interface_name
        if service_nat_acl.config.overload:
            nat_acl_cdb.overload.create()
        elif service_nat_acl.config.overload is False:
            if nat_acl_cdb.overload.exists():
                nat_acl_cdb.overload.delete()

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
        for i in nso_props.service.oc_sys__system.aaa.authorization.config.authorization_method:
            if i == 'TACACS_ALL':
                if not authorization_method_cdb.tacacsplus.exists():
                    authorization_method_cdb.tacacsplus.create()
            elif i == 'LOCAL':
                if not authorization_method_cdb.local.exists():
                    authorization_method_cdb.local.create()
            else:
                raise ValueError('XE aaa authorization must be TACACS_ALL or LOCAL')

    device_cdb = nso_props.root.devices.device[nso_props.device_name].config
    # Services
    # service ip domain lookup
    if nso_props.service.oc_sys__system.services.config.ip_domain_lookup is False:
        device_cdb.ios__ip.domain.lookup_conf.lookup = False
    elif nso_props.service.oc_sys__system.services.config.ip_domain_lookup is True:
        device_cdb.ios__ip.domain.lookup_conf.lookup = True
    # ip gratuitous arps
    if nso_props.service.oc_sys__system.services.config.ip_gratuitous_arps:
        device_cdb.ios__ip.gratuitous_arps_conf.gratuitous_arps = True
    elif nso_props.service.oc_sys__system.services.config.ip_gratuitous_arps is False:
        device_cdb.ios__ip.gratuitous_arps_conf.gratuitous_arps = None
    # service password-encryption
    if nso_props.service.oc_sys__system.services.config.service_password_encryption:
        device_cdb.ios__service.password_encryption.create()
    elif nso_props.service.oc_sys__system.services.config.service_password_encryption is False:
        if device_cdb.ios__service.password_encryption.exists():
            device_cdb.ios__service.password_encryption.delete()
    # login on-success
    if nso_props.service.oc_sys__system.services.login_security_policy.config.on_success:
        device_cdb.ios__login.on_success.log.create()
    elif nso_props.service.oc_sys__system.services.login_security_policy.config.on_success is False:
        if device_cdb.ios__login.on_success.log.exists():
            device_cdb.ios__login.on_success.log.delete()
    # login on-failure
    if nso_props.service.oc_sys__system.services.login_security_policy.config.on_failure:
        device_cdb.ios__login.on_failure.log.create()
    elif nso_props.service.oc_sys__system.services.login_security_policy.config.on_failure is False:
        if device_cdb.ios__login.on_failure.log.exists():
            device_cdb.ios__login.on_failure.log.delete()
    # login block-for
    if nso_props.service.oc_sys__system.services.login_security_policy.block_for.config.seconds and \
            nso_props.service.oc_sys__system.services.login_security_policy.block_for.config.attempts and \
            nso_props.service.oc_sys__system.services.login_security_policy.block_for.config.within:
        device_cdb.ios__login.block_for.seconds = nso_props.service.oc_sys__system.services.login_security_policy.block_for.config.seconds
        device_cdb.ios__login.block_for.attempts = nso_props.service.oc_sys__system.services.login_security_policy.block_for.config.attempts
        device_cdb.ios__login.block_for.within = nso_props.service.oc_sys__system.services.login_security_policy.block_for.config.within
    # archive logging
    if nso_props.service.oc_sys__system.services.config.archive_logging:
        device_cdb.ios__archive.log.config.logging.enable.create()
    elif nso_props.service.oc_sys__system.services.config.archive_logging is False:
        if device_cdb.ios__archive.log.config.logging.enable.exists():
            device_cdb.ios__archive.delete()
    # boot network
    if nso_props.service.oc_sys__system.services.boot_network.config.bootnetwork_enabled == "DISABLED":
        if len(device_cdb.ios__boot.network.list) != 0 or \
           len(device_cdb.ios__boot.network.list_flash.flash) != 0 or \
           device_cdb.ios__boot.network.remote_url:
            device_cdb.ios__boot.network.delete()
    # IP bootp server
    if nso_props.service.oc_sys__system.services.config.ip_bootp_server:
        device_cdb.ios__ip.bootp.server = True
    elif nso_props.service.oc_sys__system.services.config.ip_bootp_server is False:
        device_cdb.ios__ip.bootp.server = False
    # IP DNS server
    if nso_props.service.oc_sys__system.services.config.ip_dns_server:
        device_cdb.ios__ip.dns.server.create()
    elif nso_props.service.oc_sys__system.services.config.ip_dns_server is False:
        if device_cdb.ios__ip.dns.server.exists():
            device_cdb.ios__ip.dns.server.delete()
    # IP identd
    if nso_props.service.oc_sys__system.services.config.ip_identd:
        device_cdb.ios__ip.identd.create()
    elif nso_props.service.oc_sys__system.services.config.ip_identd is False:
        if device_cdb.ios__ip.identd.exists():
            device_cdb.ios__ip.identd.delete()
    # IP rcmd RCP enable
    if nso_props.service.oc_sys__system.services.config.ip_rcmd_rcp_enable:
        device_cdb.ios__ip.rcmd.rcp_enable.create()
    elif nso_props.service.oc_sys__system.services.config.ip_rcmd_rcp_enable is False:
        if device_cdb.ios__ip.rcmd.rcp_enable.exists():
            device_cdb.ios__ip.rcmd.rcp_enable.delete()
    # IP rcmd RSH enable
    if nso_props.service.oc_sys__system.services.config.ip_rcmd_rsh_enable:
        device_cdb.ios__ip.rcmd.rsh_enable.create()
    elif nso_props.service.oc_sys__system.services.config.ip_rcmd_rsh_enable is False:
        if device_cdb.ios__ip.rcmd.rsh_enable.exists():
            device_cdb.ios__ip.rcmd.rsh_enable.delete()
    # service finger
    if nso_props.service.oc_sys__system.services.config.finger:
        if not device_cdb.ios__ip.finger.exists():
            device_cdb.ios__ip.finger.create()
    elif nso_props.service.oc_sys__system.services.config.finger is False:
        if device_cdb.ios__ip.finger.exists():
            device_cdb.ios__ip.finger.delete()
    # service config
    if nso_props.service.oc_sys__system.services.config.service_config:
        device_cdb.ios__service.config.create()
    elif nso_props.service.oc_sys__system.services.config.service_config is False:
        if device_cdb.ios__service.config.exists():
            device_cdb.ios__service.config.delete()
    # service-tcp-small-servers
    if nso_props.service.oc_sys__system.services.config.service_tcp_small_servers:
        device_cdb.ios__service.tcp_small_servers.create()
    elif nso_props.service.oc_sys__system.services.config.service_tcp_small_servers is False:
        if device_cdb.ios__service.tcp_small_servers.exists():
            device_cdb.ios__service.tcp_small_servers.delete()
    # service-udp-small-servers
    if nso_props.service.oc_sys__system.services.config.service_udp_small_servers:
        device_cdb.ios__service.udp_small_servers.create()
    elif nso_props.service.oc_sys__system.services.config.service_udp_small_servers is False:
        if device_cdb.ios__service.udp_small_servers.exists():
            device_cdb.ios__service.udp_small_servers.delete()
    # service pad
    if nso_props.service.oc_sys__system.services.config.service_pad:
        device_cdb.ios__service.conf.pad = True
    elif nso_props.service.oc_sys__system.services.config.service_pad is False:
        device_cdb.ios__service.conf.pad = False
    # service password-encryption
    if nso_props.service.oc_sys__system.services.config.service_password_encryption:
        if not device_cdb.ios__service.password_encryption.exists():
            device_cdb.ios__service.password_encryption.create()
    elif nso_props.service.oc_sys__system.services.config.service_password_encryption is False:
        if device_cdb.ios__service.password_encryption.exists():
            device_cdb.ios__service.password_encryption.delete()
    # UDLD
    if nso_props.service.oc_sys__system.services.udld.config.udld == "ENABLED":
        device_cdb.ios__udld.enable.create()
    elif nso_props.service.oc_sys__system.services.udld.config.udld == "AGGRESSIVE":
        device_cdb.ios__udld.aggressive.create()
    elif nso_props.service.oc_sys__system.services.udld.config.udld == "DISABLED":
        if device_cdb.ios__udld.enable.exists():
            device_cdb.ios__udld.enable.delete()
        elif device_cdb.ios__udld.aggressive.exists():
            device_cdb.ios__udld.aggressive.delete()
    if nso_props.service.oc_sys__system.services.udld.config.message_time:
        device_cdb.ios__udld.message.time = nso_props.service.oc_sys__system.services.udld.config.message_time
    if nso_props.service.oc_sys__system.services.udld.config.recovery == "ENABLED":
        device_cdb.ios__udld.recovery.create()
    elif nso_props.service.oc_sys__system.services.udld.config.udld == "DISABLED":
        if device_cdb.ios__udld.recovery.exists():
            device_cdb.ios__udld.recovery.delete()
    if nso_props.service.oc_sys__system.services.udld.config.recovery_interval:
        device_cdb.ios__udld.recovery_conf.recovery.interval = nso_props.service.oc_sys__system.services.udld.config.recovery_interval
    # DHCP Snooping
    if nso_props.service.oc_sys__system.services.dhcp_snooping.global_config.config.enable == "ENABLED":
        if not device_cdb.ios__ip.dhcp.snooping_conf.snooping.exists():
            device_cdb.ios__ip.dhcp.snooping_conf.snooping.create()
    elif nso_props.service.oc_sys__system.services.dhcp_snooping.global_config.config.enable == "DISABLED":
        if device_cdb.ios__ip.dhcp.snooping_conf.snooping.exists():
            device_cdb.ios__ip.dhcp.snooping_conf.snooping.delete()
    if len(nso_props.service.oc_sys__system.services.dhcp_snooping.vlans) > 0:
        for vlan in nso_props.service.oc_sys__system.services.dhcp_snooping.vlans:
            vlan_id = vlan.vlan_id
            vlan_status = vlan.config.enable
            if vlan_status == 'ENABLED':
                if vlan_id not in device_cdb.ios__ip.dhcp.snooping.vlan.as_list():
                    device_cdb.ios__ip.dhcp.snooping.vlan.create(vlan_id)
            elif vlan_status == 'DISABLED':
                if vlan_id in device_cdb.ios__ip.dhcp.snooping.vlan.as_list():
                    device_cdb.ios__ip.dhcp.snooping.vlan.remove(vlan_id)
    # DAI
    if len(nso_props.service.oc_sys__system.services.dynamic_arp_inspection.vlans) > 0:
        for vlan in nso_props.service.oc_sys__system.services.dynamic_arp_inspection.vlans:
            vlan_id = vlan.vlan_id
            vlan_status = vlan.config.enable
            if vlan_status == 'ENABLED':
                if vlan_id not in device_cdb.ios__ip.arp.inspection.vlan.as_list():
                    device_cdb.ios__ip.arp.inspection.vlan.create(vlan_id)
            elif vlan_status == 'DISABLED':
                if vlan_id in device_cdb.ios__ip.arp.inspection.vlan.as_list():
                    device_cdb.ios__ip.arp.inspection.vlan.remove(vlan_id)
    # service http
    if nso_props.service.oc_sys__system.services.http.config.http_enabled:
        device_cdb.ios__ip.http.server = True
    elif nso_props.service.oc_sys__system.services.http.config.http_enabled is False:
        device_cdb.ios__ip.http.server = False
    if nso_props.service.oc_sys__system.services.http.config.https_enabled:
        device_cdb.ios__ip.http.secure_server = True
    elif nso_props.service.oc_sys__system.services.http.config.https_enabled is False:
        device_cdb.ios__ip.http.secure_server = False
    if nso_props.service.oc_sys__system.services.http.config.ip_http_max_connections:
        device_cdb.ios__ip.http.max_connections = nso_props.service.oc_sys__system.services.http.config.ip_http_max_connections
    if nso_props.service.oc_sys__system.services.http.config.ip_http_secure_ciphersuite:
        for suite in nso_props.service.oc_sys__system.services.http.config.ip_http_secure_ciphersuite:
            device_cdb.ios__ip.http.secure_ciphersuite.create(suite.replace('oc-system-ext:', ''))
    if nso_props.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.connection and nso_props.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.life and nso_props.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.requests:
        device_cdb.ios__ip.http.timeout_policy.idle = nso_props.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.connection
        device_cdb.ios__ip.http.timeout_policy.life = nso_props.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.life
        device_cdb.ios__ip.http.timeout_policy.requests = nso_props.service.oc_sys__system.services.http.ip_http_timeout_policy.idle.config.requests
    # object tracking
    if len(nso_props.service.oc_sys__system.services.object_tracking.object_track) > 0:
        for object_track in nso_props.service.oc_sys__system.services.object_tracking.object_track:
            device_cdb.ios__track.track_object.create(str(object_track.id))
            if object_track.type == 'INTERFACE':
                interface_type, interface_number = get_interface_type_and_number(
                    object_track.config.track_interface)
                int_num = str(object_track.config.track_interface).replace(interface_type, '')
                setattr(device_cdb.ios__track.track_object[str(object_track.id)].interface, interface_type, int_num)
                if str(object_track.config.track_parameter) == 'LINE-PROTOCOL':
                    device_cdb.ios__track.track_object[str(object_track.id)].interface.line_protocol.create()
                elif str(object_track.config.track_parameter) == 'IP-ROUTING':
                    device_cdb.ios__track.track_object[str(object_track.id)].interface.ip.routing.create()
                else:
                    raise ValueError('Invalid track-parameter')
            else:
                raise ValueError('Invalid object_track type')
    if nso_props.service.oc_sys__system.services.object_tracking.config.timer.interface_timer:
        device_cdb.ios__track.timer.interface.seconds = nso_props.service.oc_sys__system.services.object_tracking.config.timer.interface_timer
    # key-chain
    if len(nso_props.service.oc_sys__system.services.key_chains.key_chain) > 0:
        for kc in nso_props.service.oc_sys__system.services.key_chains.key_chain:
            name = kc.name
            # Type is NA (default)
            if kc.type == 'NOT_APPLICABLE':
                device_cdb.ios__key.chain.create(name)
                for kc_id in kc.keys:
                    key_id = str(kc_id.id)
                    key_string = kc_id.config.key_string
                    crypto_alg = kc_id.config.cryptographic_algorithm
                    device_cdb.ios__key.chain[name].key.create(key_id)
                    device_cdb.ios__key.chain[name].key[key_id].key_string.type = '0'
                    device_cdb.ios__key.chain[name].key[key_id].key_string.secret = key_string
                    device_cdb.ios__key.chain[name].key[key_id].cryptographic_algorithm = str(crypto_alg)
                    # accept_lifetime
                    global_accept_start_time = kc_id.config.accept_lifetime.start_time
                    global_accept_start_date = kc_id.config.accept_lifetime.start_date
                    global_accept_start_month = kc_id.config.accept_lifetime.start_month
                    global_accept_start_year = kc_id.config.accept_lifetime.start_year
                    global_accept_duration = kc_id.config.accept_lifetime.duration
                    global_accept_infinite = kc_id.config.accept_lifetime.infinite
                    local_accept_start_time = kc_id.config.accept_lifetime.local.start_time
                    local_accept_start_month = kc_id.config.accept_lifetime.local.start_month
                    local_accept_start_date = kc_id.config.accept_lifetime.local.start_date
                    local_accept_start_year = kc_id.config.accept_lifetime.local.start_year
                    local_accept_duration = kc_id.config.accept_lifetime.local.duration
                    local_accept_infinite = kc_id.config.accept_lifetime.local.infinite
                    if global_accept_start_time is None and global_accept_start_month is None and global_accept_start_date is None and global_accept_start_year is None:
                        accept_is_global = False
                    elif local_accept_start_time is None and local_accept_start_month is None and local_accept_start_date is None and local_accept_start_year is None:
                        accept_is_global = True
                    else:
                        raise ValueError('Invalid key-chain accept global/local settings.')
                    if accept_is_global == True:
                        device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.start_time = global_accept_start_time
                        device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.start_date = global_accept_start_date
                        device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.start_month = global_accept_start_month
                        device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.start_year = global_accept_start_year
                        global_accept_stop_time = kc_id.config.accept_lifetime.stop_time
                        global_accept_stop_date = kc_id.config.accept_lifetime.stop_date
                        global_accept_stop_month = kc_id.config.accept_lifetime.stop_month
                        global_accept_stop_year = kc_id.config.accept_lifetime.stop_year
                        if global_accept_infinite == True:
                            if global_accept_duration is not None or global_accept_stop_time is not None or global_accept_stop_date is not None or global_accept_stop_year is not None:
                                raise ValueError('Invalid key-chain global accept infinite/duration/stop settings.')
                            else:
                                device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.infinite.create()
                        elif global_accept_duration is not None:
                            if global_accept_stop_time is not None or global_accept_stop_date is not None or global_accept_stop_year is not None:
                                raise ValueError('Invalid key-chain global accept duration/stop settings.')
                            else:
                                device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.duration = global_accept_duration
                        elif global_accept_stop_time is not None and global_accept_stop_date is not None and global_accept_stop_year is not None:
                            device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.stop_time = global_accept_stop_time
                            device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.stop_date = global_accept_stop_date
                            device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.stop_month = global_accept_stop_month
                            device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.stop_year = global_accept_stop_year
                    elif accept_is_global == False:
                        device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.local.start_time = local_accept_start_time
                        device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.local.start_date = local_accept_start_date
                        device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.local.start_month = local_accept_start_month
                        device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.local.start_year = local_accept_start_year
                        local_accept_stop_time = kc_id.config.accept_lifetime.local.stop_time
                        local_accept_stop_date = kc_id.config.accept_lifetime.local.stop_date
                        local_accept_stop_month = kc_id.config.accept_lifetime.local.stop_month
                        local_accept_stop_year = kc_id.config.accept_lifetime.local.stop_year
                        if local_accept_infinite == True:
                            if local_accept_duration is not None or local_accept_stop_time is not None or local_accept_stop_date is not None or local_accept_stop_year is not None:
                                raise ValueError('Invalid key-chain local accept infinite/duration/stop settings.')
                            else:
                                device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.local.infinite.create()
                        elif local_accept_duration is not None:
                            if local_accept_stop_time is not None or local_accept_stop_date is not None or local_accept_stop_year is not None:
                                raise ValueError('Invalid key-chain local accept duration/stop settings.')
                            else:
                                device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.local.duration = local_accept_duration
                        elif local_accept_stop_time is not None and local_accept_stop_date is not None and local_accept_stop_year is not None:
                            device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.local.stop_time = local_accept_stop_time
                            device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.local.stop_date = local_accept_stop_date
                            device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.local.stop_month = local_accept_stop_month
                            device_cdb.ios__key.chain[name].key[key_id].accept_lifetime.local.stop_year = local_accept_stop_year
                    # send_lifetime
                    global_send_start_time = kc_id.config.send_lifetime.start_time
                    global_send_start_date = kc_id.config.send_lifetime.start_date
                    global_send_start_month = kc_id.config.send_lifetime.start_month
                    global_send_start_year = kc_id.config.send_lifetime.start_year
                    global_send_duration = kc_id.config.send_lifetime.duration
                    global_send_infinite = kc_id.config.send_lifetime.infinite
                    local_send_start_time = kc_id.config.send_lifetime.local.start_time
                    local_send_start_month = kc_id.config.send_lifetime.local.start_month
                    local_send_start_date = kc_id.config.send_lifetime.local.start_date
                    local_send_start_year = kc_id.config.send_lifetime.local.start_year
                    local_send_duration = kc_id.config.send_lifetime.local.duration
                    local_send_infinite = kc_id.config.send_lifetime.local.infinite
                    if global_send_start_time is None and global_send_start_month is None and global_send_start_date is None and global_send_start_year is None:
                        send_is_global = False
                    elif local_send_start_time is None and local_send_start_month is None and local_send_start_date is None and local_send_start_year is None:
                        send_is_global = True
                    else:
                        raise ValueError('Invalid key-chain send global/local settings.')
                    if send_is_global == True:
                        device_cdb.ios__key.chain[name].key[key_id].send_lifetime.start_time = global_send_start_time
                        device_cdb.ios__key.chain[name].key[key_id].send_lifetime.start_date = global_send_start_date
                        device_cdb.ios__key.chain[name].key[key_id].send_lifetime.start_month = global_send_start_month
                        device_cdb.ios__key.chain[name].key[key_id].send_lifetime.start_year = global_send_start_year
                        global_send_stop_time = kc_id.config.send_lifetime.stop_time
                        global_send_stop_date = kc_id.config.send_lifetime.stop_date
                        global_send_stop_month = kc_id.config.send_lifetime.stop_month
                        global_send_stop_year = kc_id.config.send_lifetime.stop_year
                        if global_send_infinite == True:
                            if global_send_duration is not None or global_send_stop_time is not None or global_send_stop_date is not None or global_send_stop_year is not None:
                                raise ValueError('Invalid key-chain global send infinite/duration/stop settings.')
                            else:
                                device_cdb.ios__key.chain[name].key[key_id].send_lifetime.infinite.create()
                        elif global_send_duration is not None:
                            if global_send_stop_time is not None or global_send_stop_date is not None or global_send_stop_year is not None:
                                raise ValueError('Invalid key-chain global send duration/stop settings.')
                            else:
                                device_cdb.ios__key.chain[name].key[key_id].send_lifetime.duration = global_send_duration
                        elif global_send_stop_time is not None and global_send_stop_date is not None and global_send_stop_year is not None:
                            device_cdb.ios__key.chain[name].key[key_id].send_lifetime.stop_time = global_send_stop_time
                            device_cdb.ios__key.chain[name].key[key_id].send_lifetime.stop_date = global_send_stop_date
                            device_cdb.ios__key.chain[name].key[key_id].send_lifetime.stop_month = global_send_stop_month
                            device_cdb.ios__key.chain[name].key[key_id].send_lifetime.stop_year = global_send_stop_year
                    elif send_is_global == False:
                        device_cdb.ios__key.chain[name].key[key_id].send_lifetime.local.start_time = local_send_start_time
                        device_cdb.ios__key.chain[name].key[key_id].send_lifetime.local.start_date = local_send_start_date
                        device_cdb.ios__key.chain[name].key[key_id].send_lifetime.local.start_month = local_send_start_month
                        device_cdb.ios__key.chain[name].key[key_id].send_lifetime.local.start_year = local_send_start_year
                        local_send_stop_time = kc_id.config.send_lifetime.local.stop_time
                        local_send_stop_date = kc_id.config.send_lifetime.local.stop_date
                        local_send_stop_month = kc_id.config.send_lifetime.local.stop_month
                        local_send_stop_year = kc_id.config.send_lifetime.local.stop_year
                        if local_send_infinite == True:
                            if local_send_duration is not None or local_send_stop_time is not None or local_send_stop_date is not None or local_send_stop_year is not None:
                                raise ValueError('Invalid key-chain local send infinite/duration/stop settings.')
                            else:
                                device_cdb.ios__key.chain[name].key[key_id].send_lifetime.local.infinite.create()
                        elif local_send_duration is not None:
                            if local_send_stop_time is not None or local_send_stop_date is not None or local_send_stop_year is not None:
                                raise ValueError('Invalid key-chain local send duration/stop settings.')
                            else:
                                device_cdb.ios__key.chain[name].key[key_id].send_lifetime.local.duration = local_send_duration
                        elif local_send_stop_time is not None and local_send_stop_date is not None and local_send_stop_year is not None:
                            device_cdb.ios__key.chain[name].key[key_id].send_lifetime.local.stop_time = local_send_stop_time
                            device_cdb.ios__key.chain[name].key[key_id].send_lifetime.local.stop_date = local_send_stop_date
                            device_cdb.ios__key.chain[name].key[key_id].send_lifetime.local.stop_month = local_send_stop_month
                            device_cdb.ios__key.chain[name].key[key_id].send_lifetime.local.stop_year = local_send_stop_year
            # Type is TCP
            elif kc.type == 'TCP':
                device_cdb.ios__key.tcp.chain.create(name)
                device_cdb.ios__key.tcp.chain[name].tcp.create()
                for kc_id in kc.keys:
                    key_id = str(kc_id.id)
                    key_string = kc_id.config.key_string
                    crypto_alg = kc_id.config.cryptographic_algorithm_tcp
                    send_id = kc_id.config.send_id
                    recv_id = kc_id.config.recv_id
                    device_cdb.ios__key.tcp.chain[name].key.create(key_id)
                    device_cdb.ios__key.tcp.chain[name].key[key_id].key_string.type = '0'
                    device_cdb.ios__key.tcp.chain[name].key[key_id].key_string.secret = key_string
                    device_cdb.ios__key.tcp.chain[name].key[key_id].cryptographic_algorithm = str(crypto_alg)
                    device_cdb.ios__key.tcp.chain[name].key[key_id].send_id = send_id
                    device_cdb.ios__key.tcp.chain[name].key[key_id].recv_id = recv_id
                    # accept_lifetime
                    global_accept_start_time = kc_id.config.accept_lifetime.start_time
                    global_accept_start_date = kc_id.config.accept_lifetime.start_date
                    global_accept_start_month = kc_id.config.accept_lifetime.start_month
                    global_accept_start_year = kc_id.config.accept_lifetime.start_year
                    global_accept_duration = kc_id.config.accept_lifetime.duration
                    global_accept_infinite = kc_id.config.accept_lifetime.infinite
                    local_accept_start_time = kc_id.config.accept_lifetime.local.start_time
                    local_accept_start_month = kc_id.config.accept_lifetime.local.start_month
                    local_accept_start_date = kc_id.config.accept_lifetime.local.start_date
                    local_accept_start_year = kc_id.config.accept_lifetime.local.start_year
                    local_accept_duration = kc_id.config.accept_lifetime.local.duration
                    local_accept_infinite = kc_id.config.accept_lifetime.local.infinite
                    if global_accept_start_time is None and global_accept_start_month is None and global_accept_start_date is None and global_accept_start_year is None:
                        accept_is_global = False
                    elif local_accept_start_time is None and local_accept_start_month is None and local_accept_start_date is None and local_accept_start_year is None:
                        accept_is_global = True
                    else:
                        raise ValueError('Invalid key-chain accept global/local settings.')
                    if accept_is_global == True:
                        device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.start_time = global_accept_start_time
                        device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.start_date = global_accept_start_date
                        device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.start_month = global_accept_start_month
                        device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.start_year = global_accept_start_year
                        global_accept_stop_time = kc_id.config.accept_lifetime.stop_time
                        global_accept_stop_date = kc_id.config.accept_lifetime.stop_date
                        global_accept_stop_month = kc_id.config.accept_lifetime.stop_month
                        global_accept_stop_year = kc_id.config.accept_lifetime.stop_year
                        if global_accept_infinite == True:
                            if global_accept_duration is not None or global_accept_stop_time is not None or global_accept_stop_date is not None or global_accept_stop_year is not None:
                                raise ValueError('Invalid key-chain global accept infinite/duration/stop settings.')
                            else:
                                device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.infinite.create()
                        elif global_accept_duration is not None:
                            if global_accept_stop_time is not None or global_accept_stop_date is not None or global_accept_stop_year is not None:
                                raise ValueError('Invalid key-chain global accept duration/stop settings.')
                            else:
                                device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.duration = global_accept_duration
                        elif global_accept_stop_time is not None and global_accept_stop_date is not None and global_accept_stop_year is not None:
                            device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.stop_time = global_accept_stop_time
                            device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.stop_date = global_accept_stop_date
                            device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.stop_month = global_accept_stop_month
                            device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.stop_year = global_accept_stop_year
                    elif accept_is_global == False:
                        device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.local.start_time = local_accept_start_time
                        device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.local.start_date = local_accept_start_date
                        device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.local.start_month = local_accept_start_month
                        device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.local.start_year = local_accept_start_year
                        local_accept_stop_time = kc_id.config.accept_lifetime.local.stop_time
                        local_accept_stop_date = kc_id.config.accept_lifetime.local.stop_date
                        local_accept_stop_month = kc_id.config.accept_lifetime.local.stop_month
                        local_accept_stop_year = kc_id.config.accept_lifetime.local.stop_year
                        if local_accept_infinite == True:
                            if local_accept_duration is not None or local_accept_stop_time is not None or local_accept_stop_date is not None or local_accept_stop_year is not None:
                                raise ValueError('Invalid key-chain local accept infinite/duration/stop settings.')
                            else:
                                device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.local.infinite.create()
                        elif local_accept_duration is not None:
                            if local_accept_stop_time is not None or local_accept_stop_date is not None or local_accept_stop_year is not None:
                                raise ValueError('Invalid key-chain local accept duration/stop settings.')
                            else:
                                device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.local.duration = local_accept_duration
                        elif local_accept_stop_time is not None and local_accept_stop_date is not None and local_accept_stop_year is not None:
                            device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.local.stop_time = local_accept_stop_time
                            device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.local.stop_date = local_accept_stop_date
                            device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.local.stop_month = local_accept_stop_month
                            device_cdb.ios__key.tcp.chain[name].key[key_id].accept_lifetime.local.stop_year = local_accept_stop_year
                    # send_lifetime
                    global_send_start_time = kc_id.config.send_lifetime.start_time
                    global_send_start_date = kc_id.config.send_lifetime.start_date
                    global_send_start_month = kc_id.config.send_lifetime.start_month
                    global_send_start_year = kc_id.config.send_lifetime.start_year
                    global_send_duration = kc_id.config.send_lifetime.duration
                    global_send_infinite = kc_id.config.send_lifetime.infinite
                    local_send_start_time = kc_id.config.send_lifetime.local.start_time
                    local_send_start_month = kc_id.config.send_lifetime.local.start_month
                    local_send_start_date = kc_id.config.send_lifetime.local.start_date
                    local_send_start_year = kc_id.config.send_lifetime.local.start_year
                    local_send_duration = kc_id.config.send_lifetime.local.duration
                    local_send_infinite = kc_id.config.send_lifetime.local.infinite
                    if global_send_start_time is None and global_send_start_month is None and global_send_start_date is None and global_send_start_year is None:
                        send_is_global = False
                    elif local_send_start_time is None and local_send_start_month is None and local_send_start_date is None and local_send_start_year is None:
                        send_is_global = True
                    else:
                        raise ValueError('Invalid key-chain send global/local settings.')
                    if send_is_global == True:
                        device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.start_time = global_send_start_time
                        device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.start_date = global_send_start_date
                        device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.start_month = global_send_start_month
                        device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.start_year = global_send_start_year
                        global_send_stop_time = kc_id.config.send_lifetime.stop_time
                        global_send_stop_date = kc_id.config.send_lifetime.stop_date
                        global_send_stop_month = kc_id.config.send_lifetime.stop_month
                        global_send_stop_year = kc_id.config.send_lifetime.stop_year
                        if global_send_infinite == True:
                            if global_send_duration is not None or global_send_stop_time is not None or global_send_stop_date is not None or global_send_stop_year is not None:
                                raise ValueError('Invalid key-chain global send infinite/duration/stop settings.')
                            else:
                                device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.infinite.create()
                        elif global_send_duration is not None:
                            if global_send_stop_time is not None or global_send_stop_date is not None or global_send_stop_year is not None:
                                raise ValueError('Invalid key-chain global send duration/stop settings.')
                            else:
                                device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.duration = global_send_duration
                        elif global_send_stop_time is not None and global_send_stop_date is not None and global_send_stop_year is not None:
                            device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.stop_time = global_send_stop_time
                            device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.stop_date = global_send_stop_date
                            device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.stop_month = global_send_stop_month
                            device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.stop_year = global_send_stop_year
                    elif send_is_global == False:
                        device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.local.start_time = local_send_start_time
                        device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.local.start_date = local_send_start_date
                        device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.local.start_month = local_send_start_month
                        device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.local.start_year = local_send_start_year
                        local_send_stop_time = kc_id.config.send_lifetime.local.stop_time
                        local_send_stop_date = kc_id.config.send_lifetime.local.stop_date
                        local_send_stop_month = kc_id.config.send_lifetime.local.stop_month
                        local_send_stop_year = kc_id.config.send_lifetime.local.stop_year
                        if local_send_infinite == True:
                            if local_send_duration is not None or local_send_stop_time is not None or local_send_stop_date is not None or local_send_stop_year is not None:
                                raise ValueError('Invalid key-chain local send infinite/duration/stop settings.')
                            else:
                                device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.local.infinite.create()
                        elif local_send_duration is not None:
                            if local_send_stop_time is not None or local_send_stop_date is not None or local_send_stop_year is not None:
                                raise ValueError('Invalid key-chain local send duration/stop settings.')
                            else:
                                device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.local.duration = local_send_duration
                        elif local_send_stop_time is not None and local_send_stop_date is not None and local_send_stop_year is not None:
                            device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.local.stop_time = local_send_stop_time
                            device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.local.stop_date = local_send_stop_date
                            device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.local.stop_month = local_send_stop_month
                            device_cdb.ios__key.tcp.chain[name].key[key_id].send_lifetime.local.stop_year = local_send_stop_year
            # Type is MACSEC
            elif kc.type == 'MACSEC':
                raise ValueError('Unsupported key-chain type: MACSEC.')
            else:
                raise ValueError('Invalid key-chain type')
    # nat pools
    if len(nso_props.service.oc_sys__system.services.nat.pools.pool) > 0:
        for service_pool in nso_props.service.oc_sys__system.services.nat.pools.pool:
            pool_cdb = device_cdb.ios__ip.nat.pool.create(service_pool.name)
            pool_cdb.start_address = service_pool.config.start_address
            pool_cdb.end_address = service_pool.config.end_address
            if service_pool.config.netmask:
                pool_cdb.netmask = service_pool.config.netmask
            elif service_pool.config.prefix_length:
                pool_cdb.prefix_length = service_pool.config.prefix_length
    # nat source inside local acl
    if len(nso_props.service.oc_sys__system.services.nat.inside.source.local_addresses_access_lists.local_addresses_access_list) > 0:
        for service_nat_acl in nso_props.service.oc_sys__system.services.nat.inside.source.local_addresses_access_lists.local_addresses_access_list:
            if not service_nat_acl.config.vrf or service_nat_acl.config.vrf == 'NONE':
                nat_acl_cdb = device_cdb.ios__ip.nat.inside.source.list.create(
                    service_nat_acl.config.local_addresses_access_list_name)
                configure_local_addresses_access_list_nat()
            else:
                nat_acl_cdb = device_cdb.ios__ip.nat.inside.source.list_vrf.list.create(
                    service_nat_acl.config.local_addresses_access_list_name, service_nat_acl.config.vrf)
                configure_local_addresses_access_list_nat()
    # clock
    if nso_props.service.oc_sys__system.clock.config.timezone_name:
        name, hours, minutes = xe_convert_timezone_string(nso_props.service.oc_sys__system.clock.config.timezone_name)
        device_cdb.ios__clock.timezone.zone = name
        device_cdb.ios__clock.timezone.hours = hours
        device_cdb.ios__clock.timezone.minutes = minutes
    # config
    if nso_props.service.oc_sys__system.config.domain_name:
        device_cdb.ios__ip.domain.name = nso_props.service.oc_sys__system.config.domain_name
    if nso_props.service.oc_sys__system.config.hostname:
        device_cdb.hostname = nso_props.service.oc_sys__system.config.hostname
    if nso_props.service.oc_sys__system.config.login_banner:
        device_cdb.banner.login = nso_props.service.oc_sys__system.config.login_banner
    if nso_props.service.oc_sys__system.config.motd_banner:
        device_cdb.banner.motd = nso_props.service.oc_sys__system.config.motd_banner
    if nso_props.service.oc_sys__system.config.enable_secret:
        device_cdb.enable.secret.secret = nso_props.service.oc_sys__system.config.enable_secret
        device_cdb.enable.secret.type = 0
    if nso_props.service.oc_sys__system.config.console_exec_timeout_seconds:
        seconds_all = int(nso_props.service.oc_sys__system.config.console_exec_timeout_seconds)
        device_cdb.ios__line.console[0].exec_timeout.minutes = str(seconds_all // 60)
        device_cdb.ios__line.console[0].exec_timeout.seconds = str(seconds_all % 60)
    if nso_props.service.oc_sys__system.config.ip_options:
        if nso_props.service.oc_sys__system.config.ip_options == "oc-system-ext:ENABLE":
            if device_cdb.ios__ip.options.drop.exists():
                device_cdb.ios__ip.options.drop.delete()
            if device_cdb.ios__ip.options.ignore.exists():
                device_cdb.ios__ip.options.ignore.delete()
        elif nso_props.service.oc_sys__system.config.ip_options == "oc-system-ext:DROP":
            if device_cdb.ios__ip.options.ignore.exists():
                device_cdb.ios__ip.options.ignore.delete()
            device_cdb.ios__ip.options.drop.create()
        elif nso_props.service.oc_sys__system.config.ip_options == "oc-system-ext:IGNORE":
            if device_cdb.ios__ip.options.drop.exists():
                device_cdb.ios__ip.options.drop.delete()
            device_cdb.ios__ip.options.ignore.create()
    if nso_props.service.oc_sys__system.timestamps.logging.config.enabled and (
            nso_props.service.oc_sys__system.timestamps.logging.config.datetime or nso_props.service.oc_sys__system.timestamps.logging.config.uptime):
        if nso_props.service.oc_sys__system.timestamps.logging.config.datetime:
            dt = device_cdb.ios__service.timestamps.log.datetime.create()
            if nso_props.service.oc_sys__system.timestamps.logging.config.localtime:
                dt.localtime.create()
        else:
            device_cdb.ios__service.timestamps.log.uptime.create()
    elif nso_props.service.oc_sys__system.timestamps.logging.config.datetime and nso_props.service.oc_sys__system.timestamps.logging.config.uptime:
        raise ValueError('Can not use timestamp logging with both uptime and datetime')
    elif nso_props.service.oc_sys__system.timestamps.logging.config.enabled and (
            not nso_props.service.oc_sys__system.timestamps.logging.config.datetime or not nso_props.service.oc_sys__system.timestamps.logging.config.uptime):
        raise ValueError('Logging timestamps must use datetime or uptime')
    if nso_props.service.oc_sys__system.timestamps.debugging.config.enabled and (
            nso_props.service.oc_sys__system.timestamps.debugging.config.datetime or nso_props.service.oc_sys__system.timestamps.debugging.config.uptime):
        if nso_props.service.oc_sys__system.timestamps.debugging.config.datetime:
            dt = device_cdb.ios__service.timestamps.debug.datetime.create()
            if nso_props.service.oc_sys__system.timestamps.debugging.config.localtime:
                dt.localtime.create()
        else:
            device_cdb.ios__service.timestamps.debug.uptime.create()
    elif nso_props.service.oc_sys__system.timestamps.debugging.config.datetime and nso_props.service.oc_sys__system.timestamps.debugging.config.uptime:
        raise ValueError('Can not use timestamp debugging with both uptime and datetime')
    elif nso_props.service.oc_sys__system.timestamps.debugging.config.enabled and (
            not nso_props.service.oc_sys__system.timestamps.debugging.config.datetime or not nso_props.service.oc_sys__system.timestamps.debugging.config.uptime):
        raise ValueError('Debugging timestamps must use datetime or uptime')
    # DNS servers
    if nso_props.service.oc_sys__system.dns:
        for service_dns_server in nso_props.service.oc_sys__system.dns.servers.server:
            if service_dns_server.config.port != 53:
                raise ValueError('XE DNS servers must use port 53')
            if not service_dns_server.config.use_vrf or nso_props.service.oc_netinst__network_instances.network_instance[
                service_dns_server.config.use_vrf].config.type == 'oc-ni-types:DEFAULT_INSTANCE':
                device_cdb.ios__ip.name_server.name_server_list.create(service_dns_server.address)
            elif nso_props.service.oc_netinst__network_instances.network_instance[
                service_dns_server.config.use_vrf].config.type == 'oc-ni-types:L3VRF':
                if not device_cdb.ios__ip.name_server.vrf.exists(service_dns_server.config.use_vrf):
                    device_cdb.ios__ip.name_server.vrf.create(service_dns_server.config.use_vrf)
                device_cdb.ios__ip.name_server.vrf[service_dns_server.config.use_vrf].name_server_list.create(service_dns_server.address)
    # SSH server
    if nso_props.service.oc_sys__system.ssh_server.config.enable:
        for service_line_vty in device_cdb.ios__line.vty:
            service_line_vty.transport.input = ['ssh']
    elif nso_props.service.oc_sys__system.ssh_server.config.enable is False:
        for service_line_vty in device_cdb.ios__line.vty:
            if 'ssh' in service_line_vty.transport.input.as_list():
                service_line_vty.transport.input.remove('ssh')
    if nso_props.service.oc_sys__system.ssh_server.config.protocol_version == 'V2':
        device_cdb.ios__ip.ssh.version = 2
    elif nso_props.service.oc_sys__system.ssh_server.config.protocol_version == 'V1':
        device_cdb.ios__ip.ssh.version = 1
    elif nso_props.service.oc_sys__system.ssh_server.config.protocol_version == 'V1_V2':
        device_cdb.ios__ip.ssh.version = None
    if nso_props.service.oc_sys__system.ssh_server.config.rate_limit:
        raise ValueError('SSH rate-limiting is unsupported in XE')
    if nso_props.service.oc_sys__system.ssh_server.config.session_limit:
        for service_line_vty in device_cdb.ios__line.vty:
            service_line_vty.session_limit = nso_props.service.oc_sys__system.ssh_server.config.session_limit
    if nso_props.service.oc_sys__system.ssh_server.config.timeout:
        seconds_all = int(nso_props.service.oc_sys__system.ssh_server.config.timeout)
        for service_line_vty in device_cdb.ios__line.vty:
            service_line_vty.exec_timeout.minutes = str(seconds_all // 60)
            service_line_vty.exec_timeout.seconds = str(seconds_all % 60)
    if nso_props.service.oc_sys__system.ssh_server.config.absolute_timeout_minutes:
        for service_line_vty in device_cdb.ios__line.vty:
            service_line_vty.absolute_timeout = nso_props.service.oc_sys__system.ssh_server.config.absolute_timeout_minutes
    if nso_props.service.oc_sys__system.ssh_server.config.ssh_timeout:
        device_cdb.ios__ip.ssh.time_out = nso_props.service.oc_sys__system.ssh_server.config.ssh_timeout
    if nso_props.service.oc_sys__system.ssh_server.config.ssh_source_interface:
        interface_type, interface_number = get_interface_type_and_number(
            nso_props.service.oc_sys__system.ssh_server.config.ssh_source_interface)
        device_cdb.ios__ip.ssh.source_interface[interface_type] = interface_number
    if nso_props.service.oc_sys__system.ssh_server.algorithm.config.encryption:
        device_cdb.ios__ip.ssh.server.algorithm.encryption.delete()
        for enc in nso_props.service.oc_sys__system.ssh_server.algorithm.config.encryption:
            if enc == 'triple-des-cbc':
                device_cdb.ios__ip.ssh.server.algorithm.encryption.create(enc.replace('triple-des-cbc', '3des-cbc'))
            else:
                device_cdb.ios__ip.ssh.server.algorithm.encryption.create(enc)
    if nso_props.service.oc_sys__system.ssh_server.algorithm.config.mac:
        device_cdb.ios__ip.ssh.server.algorithm.mac.delete()
        for mac in nso_props.service.oc_sys__system.ssh_server.algorithm.config.mac:
            device_cdb.ios__ip.ssh.server.algorithm.mac.create(mac)
    # NTP
    if nso_props.service.oc_sys__system.ntp.config.enabled:
        if nso_props.service.oc_sys__system.ntp.config.ntp_source_address:
            ip_name_dict = xe_system_get_interface_ip_address(self, nso_props)
            if ip_name_dict.get(nso_props.service.oc_sys__system.ntp.config.ntp_source_address):
                interface_type, interface_number = get_interface_type_and_number(
                    ip_name_dict.get(nso_props.service.oc_sys__system.ntp.config.ntp_source_address))
                device_cdb.ios__ntp.source[interface_type] = interface_number
        if nso_props.service.oc_sys__system.ntp.config.enable_ntp_auth:
            device_cdb.ios__ntp.authenticate.create()
        elif nso_props.service.oc_sys__system.ntp.config.enable_ntp_auth is False:
            if device_cdb.ios__ntp.authenticate.exists():
                device_cdb.ios__ntp.authenticate.delete()
        if nso_props.service.oc_sys__system.ntp.config.ntp_enable_logging:
            device_cdb.ios__ntp.logging.create()
        elif nso_props.service.oc_sys__system.ntp.config.ntp_enable_logging is False:
            if device_cdb.ios__ntp.logging.exists():
                device_cdb.ios__ntp.logging.delete()
        if nso_props.service.oc_sys__system.ntp.ntp_keys.ntp_key:
            for service_ntp_key in nso_props.service.oc_sys__system.ntp.ntp_keys.ntp_key:
                self.log.info(f"service_ntp_key.config.key_type {service_ntp_key.config.key_type}")
                if service_ntp_key.config.key_type == 'oc-sys:NTP_AUTH_MD5':
                    key = device_cdb.ios__ntp.authentication_key.create(service_ntp_key.config.key_id)
                    key.md5.secret = service_ntp_key.config.key_value
                    device_cdb.ios__ntp.trusted_key.create(service_ntp_key.config.key_id)
                else:
                    raise ValueError('XE NTP must use MD5 authentication and use NTP key type NTP_AUTH_MD5.')
        if nso_props.service.oc_sys__system.ntp.servers.server:
            for service_ntp_server in nso_props.service.oc_sys__system.ntp.servers.server:
                if service_ntp_server.config.ntp_use_vrf:
                    if nso_props.service.oc_netinst__network_instances.network_instance[
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
                    elif nso_props.service.oc_netinst__network_instances.network_instance[
                        service_ntp_server.config.ntp_use_vrf].config.type == 'oc-ni-types:DEFAULT_INSTANCE':
                        if service_ntp_server.config.association_type == 'SERVER':
                            if not device_cdb.ios__ntp.server.peer_list.exists(service_ntp_server.config.address):
                                device_cdb.ios__ntp.server.peer_list.create(service_ntp_server.config.address)
                            peer_cdb = device_cdb.ios__ntp.server.peer_list[service_ntp_server.config.address]
                            if service_ntp_server.config.ntp_source_address:
                                xe_configure_ntp_server_source_address(self, nso_props, service_ntp_server, peer_cdb)
                            xe_configure_ntp_server(service_ntp_server, peer_cdb)
                        elif service_ntp_server.config.association_type == 'PEER':
                            if not device_cdb.ios__ntp.peer.peer_list.exists(service_ntp_server.config.address):
                                device_cdb.ios__ntp.peer.peer_list.create(service_ntp_server.config.address)
                            peer_cdb = device_cdb.ios__ntp.peer.peer_list[service_ntp_server.config.address]
                            if service_ntp_server.config.ntp_source_address:
                                xe_configure_ntp_server_source_address(self, nso_props, service_ntp_server, peer_cdb)
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
                            xe_configure_ntp_server_source_address(self, nso_props, service_ntp_server, peer_cdb)
                        xe_configure_ntp_server(service_ntp_server, peer_cdb)
                    elif service_ntp_server.config.association_type == 'PEER':
                        if not device_cdb.ios__ntp.peer.peer_list.exists(service_ntp_server.config.address):
                            device_cdb.ios__ntp.peer.peer_list.create(service_ntp_server.config.address)
                        peer_cdb = device_cdb.ios__ntp.peer.peer_list[service_ntp_server.config.address]
                        if service_ntp_server.config.ntp_source_address:
                            xe_configure_ntp_server_source_address(self, nso_props, service_ntp_server, peer_cdb)
                        xe_configure_ntp_server(service_ntp_server, peer_cdb)
                    else:
                        raise ValueError('XE supports ntp association types of SERVER and PEER')

    elif nso_props.service.oc_sys__system.ntp.config.enabled is False:
        if len(device_cdb.ios__ntp.server.peer_list) > 0:
            device_cdb.ios__ntp.server.peer_list.delete()
        if len(device_cdb.ios__ntp.peer.peer_list) > 0:
            device_cdb.ios__ntp.peer.peer_list.delete()
        if len(device_cdb.ios__ntp.server.vrf) > 0:
            device_cdb.ios__ntp.server.vrf.delete()
        if len(device_cdb.ios__ntp.peer.vrf) > 0:
            device_cdb.ios__ntp.peer.vrf.delete()
    # Logging
    if nso_props.service.oc_sys__system.logging.buffered.config.severity and nso_props.service.oc_sys__system.logging.buffered.config.buffer_size:
        device_cdb.ios__logging.buffered.buffer_size = nso_props.service.oc_sys__system.logging.buffered.config.buffer_size
        device_cdb.ios__logging.buffered.severity_level = severity_levels_oc_to_xe.get(str(nso_props.service.oc_sys__system.logging.buffered.config.severity))
    elif nso_props.service.oc_sys__system.logging.buffered.config.enabled is False:
        device_cdb.ios__logging.buffered.buffer_size = None
        device_cdb.ios__logging.buffered.severity_level = None
    logging_facility = set()
    remote_server_severity = list()
    if nso_props.service.oc_sys__system.logging.console.config.enabled is False:
        device_cdb.ios__logging.console.severity_level = None
    elif nso_props.service.oc_sys__system.logging.console.selectors.selector:
        if len(nso_props.service.oc_sys__system.logging.console.selectors.selector) == 1:
            key0 = nso_props.service.oc_sys__system.logging.console.selectors.selector.keys()[0]
            device_cdb.ios__logging.console.severity_level = severity_levels_oc_to_xe.get(
                str(nso_props.service.oc_sys__system.logging.console.selectors.selector[key0].severity))
            logging_facility.add(str(nso_props.service.oc_sys__system.logging.console.selectors.selector[key0].facility))
        else:
            raise ValueError('XE supports 1 console logging selector.')
    if nso_props.service.oc_sys__system.logging.terminal_monitor.selectors.selector:
        if len(nso_props.service.oc_sys__system.logging.terminal_monitor.selectors.selector) == 1:
            key0 = nso_props.service.oc_sys__system.logging.terminal_monitor.selectors.selector.keys()[0]
            device_cdb.ios__logging.monitor.severity_level = severity_levels_oc_to_xe.get(
                str(nso_props.service.oc_sys__system.logging.terminal_monitor.selectors.selector[key0].severity))
            logging_facility.add(
                str(nso_props.service.oc_sys__system.logging.terminal_monitor.selectors.selector[key0].facility))
        else:
            raise ValueError('XE supports 1 terminal-monitor logging selector.')

    if nso_props.service.oc_sys__system.logging.remote_servers.remote_server:
        for service_remote_server in nso_props.service.oc_sys__system.logging.remote_servers.remote_server:
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
            if not service_remote_server.config.use_vrf or nso_props.service.oc_netinst__network_instances.network_instance[
                service_remote_server.config.use_vrf].config.type == 'oc-ni-types:DEFAULT_INSTANCE':
                device_cdb.ios__logging.host.ipv4.create(service_remote_server.config.host)
                if service_remote_server.config.source_address:
                    ip_name_dict = xe_system_get_interface_ip_address(self, nso_props)
                    if ip_name_dict.get(service_remote_server.config.source_address):
                        interface_type, interface_number = get_interface_type_and_number(
                            ip_name_dict.get(service_remote_server.config.source_address))
                        device_cdb.ios__logging.source_interface.create(f"{interface_type}{interface_number}")
            elif nso_props.service.oc_netinst__network_instances.network_instance[
                service_remote_server.config.use_vrf].config.type == 'oc-ni-types:L3VRF':
                device_cdb.ios__logging.host.ipv4_vrf.create((service_remote_server.config.host, service_remote_server.config.use_vrf))
                if service_remote_server.config.source_address:
                    ip_name_dict = xe_system_get_interface_ip_address(self, nso_props)
                    if ip_name_dict.get(service_remote_server.config.source_address):
                        interface_type, interface_number = get_interface_type_and_number(
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
    # gather group and server configurations
    if len(nso_props.service.oc_sys__system.aaa.server_groups.server_group) > 0:
        server_groups = list()
        for group in nso_props.service.oc_sys__system.aaa.server_groups.server_group:
            server_group = dict(name=group.name, type=group.config.type, servers=[])
            for server in group.servers.server:
                if group.config.type == 'oc-aaa:TACACS':
                    server_info = dict(address=server.address,
                                       name=server.config.name,
                                       timeout=server.config.timeout,
                                       port=server.tacacs.config.port,
                                       secret_key=server.tacacs.config.secret_key,
                                       source_address=server.tacacs.config.source_address)
                elif group.config.type == 'oc-aaa:RADIUS':
                    server_info = dict(address=server.address,
                                       name=server.config.name,
                                       timeout=server.config.timeout,
                                       acct_port=server.radius.config.acct_port,
                                       auth_port=server.radius.config.auth_port,
                                       retransmit_attempts=server.radius.config.retransmit_attempts,
                                       secret_key=server.radius.config.secret_key,
                                       source_address=server.radius.config.source_address)
                server_group['servers'].append(server_info)
            server_groups.append(server_group)

        # configure groups
        for g in server_groups:
            if g.get('type') == 'oc-aaa:TACACS':
                device_cdb_server = device_cdb.ios__tacacs.server
                device_cdb_group = device_cdb.ios__aaa.group.server.tacacs_plus
            elif g.get('type') == 'oc-aaa:RADIUS':
                device_cdb_server = device_cdb.ios__radius.server
                device_cdb_group = device_cdb.ios__aaa.group.server.radius

            if not device_cdb_group.exists((g.get('name'))):
                device_cdb_group.create((g.get('name')))
            group = device_cdb_group[(g.get('name'))]

            source_address = ''
            for s in g['servers']:
                # create and configure server
                if not device_cdb_server.exists((s.get('name'))):
                    device_cdb_server.create(s.get('name'))
                server = device_cdb_server[(s.get('name'))]
                if g.get('type') == 'oc-aaa:TACACS':
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
                elif g.get('type') == 'oc-aaa:RADIUS':
                    if s.get('acct_port'):
                        server.address.ipv4.acct_port = s.get('acct_port')
                    if s.get('auth_port'):
                        server.address.ipv4.auth_port = s.get('auth_port')
                    if s.get('retransmit_attempts'):
                        server.retransmit = s.get('retransmit_attempts')
                    if s.get('address'):
                        server.address.ipv4.host = s.get('address')
                    server.key.type = '0'
                    if s.get('secret_key'):
                        server.key.secret = s.get('secret_key')
                    if server.timeout:
                        server.timeout = s.get('timeout')
                    if s.get('source_address'):
                        source_address = s.get('source_address')
                # add server to group
                if not group.server.name.exists(s.get('name')):
                    group.server.name.create(s.get('name'))
            # add source_address to group
            if source_address:
                ip_name_dict = xe_system_get_interface_ip_address(self, nso_props)
                if ip_name_dict.get(source_address):
                    interface_name, interface_number = get_interface_type_and_number(
                        ip_name_dict.get(source_address))
                    if g.get('type') == 'oc-aaa:TACACS':
                        setattr(group.ip.tacacs.source_interface, interface_name, interface_number)
                    elif g.get('type') == 'oc-aaa:RADIUS':
                        setattr(group.ip.radius.source_interface, interface_name, interface_number)
    # aaa authentication
    if nso_props.service.oc_sys__system.aaa.authentication.admin_user.config.admin_password:
        if not device_cdb.username.exists('admin'):
            device_cdb.username.create('admin')
        admin_user = device_cdb.username['admin']
        admin_user.privilege = 15
        admin_user.secret.secret = nso_props.service.oc_sys__system.aaa.authentication.admin_user.config.admin_password
        admin_user.secret.type = 0
        admin_user.password.secret = None
        admin_user.password.type = None
    if len(nso_props.service.oc_sys__system.aaa.authentication.config.authentication_method) > 0:
        if not device_cdb.ios__aaa.new_model.exists():
            device_cdb.ios__aaa.new_model.create()
        if not device_cdb.ios__aaa.authentication.login.exists('default'):
            device_cdb.ios__aaa.authentication.login.create('default')
        aaa_login = device_cdb.ios__aaa.authentication.login['default']
        aaa_configure_methods(aaa_login, nso_props.service.oc_sys__system.aaa.authentication.config.authentication_method)
    if len(nso_props.service.oc_sys__system.aaa.authentication.oc_system_ext__authentication_lists_login.config.authentication_method) > 0:
        if not device_cdb.ios__aaa.new_model.exists():
            device_cdb.ios__aaa.new_model.create()
        if not device_cdb.ios__aaa.authentication.login.exists(nso_props.service.oc_sys__system.aaa.authentication.oc_system_ext__authentication_lists_login.config.name):
            device_cdb.ios__aaa.authentication.login.create(nso_props.service.oc_sys__system.aaa.authentication.oc_system_ext__authentication_lists_login.config.name)
        aaa_login = device_cdb.ios__aaa.authentication.login[nso_props.service.oc_sys__system.aaa.authentication.oc_system_ext__authentication_lists_login.config.name]
        aaa_configure_methods(aaa_login, nso_props.service.oc_sys__system.aaa.authentication.oc_system_ext__authentication_lists_login.config.authentication_method)
    if nso_props.service.oc_sys__system.aaa.authentication.users.user:
        for service_user in nso_props.service.oc_sys__system.aaa.authentication.users.user:
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
    if nso_props.service.oc_sys__system.aaa.authorization.events.event:
        if not device_cdb.ios__aaa.new_model.exists():
            device_cdb.ios__aaa.new_model.create()
        for i in nso_props.service.oc_sys__system.aaa.authorization.events.event:
            if i.event_type == 'oc-aaa-types:AAA_AUTHORIZATION_EVENT_CONFIG':
                if not device_cdb.ios__aaa.authorization.exec.exists('default'):
                    device_cdb.ios__aaa.authorization.exec.create('default')
                authorization_method_cdb = device_cdb.ios__aaa.authorization.exec['default']
                if nso_props.service.oc_sys__system.aaa.authorization.config.authorization_method:
                    aaa_configure_methods(authorization_method_cdb, nso_props.service.oc_sys__system.aaa.authorization.config.authorization_method)
            elif i.event_type == 'oc-aaa-types:AAA_AUTHORIZATION_EVENT_COMMAND':
                if not device_cdb.ios__aaa.authorization.config_commands:
                    device_cdb.ios__aaa.authorization.config_commands.create()
                if not device_cdb.ios__aaa.authorization.commands.exists('default'):
                    device_cdb.ios__aaa.authorization.commands.create('default')
                authorization_method_cdb = device_cdb.ios__aaa.authorization.commands['default']
                authorization_method_cdb.level = 15
                if nso_props.service.oc_sys__system.aaa.authorization.config.authentication_method:
                    xe_configure_authorization_method()
            else:
                raise ValueError('XE aaa authorization.events.event must be oc-aaa-types:AAA_AUTHORIZATION_EVENT_CONFIG or oc-aaa-types:AAA_AUTHORIZATION_EVENT_COMMAND')
    # aaa accounting
    aaa_accounting_accounting_methods = list()
    aaa_accounting_events = list()
    if nso_props.service.oc_sys__system.aaa.accounting.config.accounting_method:
        if not device_cdb.ios__aaa.new_model.exists():
            device_cdb.ios__aaa.new_model.create()
        for i in nso_props.service.oc_sys__system.aaa.accounting.config.accounting_method:
            aaa_accounting_accounting_methods.append(i)
    if nso_props.service.oc_sys__system.aaa.accounting.events.event:
        for i in nso_props.service.oc_sys__system.aaa.accounting.events.event:
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


def xe_configure_ntp_server_source_address(self, nso_props, service_ntp_server, peer_cdb) -> None:
    ip_name_dict = xe_system_get_interface_ip_address(self, nso_props)
    if ip_name_dict.get(service_ntp_server.config.ntp_source_address):
        interface_type, interface_number = get_interface_type_and_number(
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
    elif service_ntp_server.config.iburst is False:
        if peer_cdb.iburst.exists():
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
