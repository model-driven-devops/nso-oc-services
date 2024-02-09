# -*- mode: python; python-indent: 4 -*-
from translation.openconfig_xe.xe_acls import xe_acls_interfaces_program_service
from translation.openconfig_xe.xe_acls import xe_acls_lines_program_service
from translation.openconfig_xe.xe_acls import xe_acls_ntp_program_service
from translation.openconfig_xe.xe_acls import xe_acls_program_service
from translation.openconfig_xe.xe_interfaces import xe_interfaces_program_service
from translation.openconfig_xe.xe_network_instances import xe_network_instances_program_service
from translation.openconfig_xe.xe_routing_policy import xe_routing_policy_program_service
from translation.openconfig_xe.xe_system import xe_system_program_service
from translation.openconfig_xe.xe_stp import xe_stp_program_service
from translation.openconfig_xe.xe_qos import xe_qos_program_service

def check_xe_features(oc_self, nso_props) -> None:
    """
    Check the OC - XE features.
    """
    if len(nso_props.service.oc_if__interfaces.interface) > 0:
        xe_interfaces_program_service(oc_self, nso_props)

    # Spanning-tree
    if nso_props.service.oc_stp__stp.oc_stp__global.config.enabled_protocol.exists():
        xe_stp_program_service(oc_self, nso_props)
    # OpenConfig ACL
    if len(nso_props.service.oc_acl__acl.acl_sets.acl_set) > 0:
        xe_acls_program_service(oc_self, nso_props)
    if len(nso_props.service.oc_acl__acl.interfaces.interface) > 0:
        xe_acls_interfaces_program_service(oc_self, nso_props)
    if len(nso_props.service.oc_acl__acl.oc_acl_ext__lines.line) > 0:
        xe_acls_lines_program_service(oc_self, nso_props)
    xe_acls_ntp_program_service(oc_self, nso_props)

    # OpenConfig routing-policy
    if nso_props.service.oc_rpol__routing_policy:
        xe_routing_policy_program_service(oc_self, nso_props)

    # OpenConfig Network Instances
    if len(nso_props.service.oc_netinst__network_instances.network_instance) > 0:
        xe_network_instances_program_service(oc_self, nso_props)

    # OpenConfig System
    xe_system_program_service(oc_self, nso_props)

    # OpenConfig QoS
    if nso_props.service.oc_qos__qos:
        xe_qos_program_service(oc_self, nso_props)

def clean_xe_cdb(nso_props) -> None:
    """
    Remove CDB lists to be repopulated with OC configs.
    """
    device = nso_props.root.devices.device[nso_props.device_name].config

    device.ios__access_list.access_list.delete()
    device.ios__ip.access_list.extended.ext_named_acl.delete()
    device.ios__ip.access_list.standard.std_named_acl.delete()
    device.ios__ip.arp.inspection.vlan.delete()
    device.ios__ip.as_path.access_list.delete()
    device.ios__ip.community_list.expanded.delete()
    device.ios__ip.community_list.standard.delete()
    device.ios__ip.dhcp.snooping.vlan.delete()
    device.ios__ip.extcommunity_list.standard.no_mode_list.delete()
    device.ios__ip.http.secure_ciphersuite.delete()
    device.ios__ip.name_server.vrf.delete()
    device.ios__ip.name_server.name_server_list.delete()
    device.ios__ip.nat.inside.source.list_vrf.list.delete()
    device.ios__ip.nat.inside.source.list.delete()
    device.ios__ip.nat.pool.delete()
    device.ios__ip.prefix_list.prefixes.delete()
    device.ios__ip.route.ip_route_forwarding_list.delete()
    device.ios__ip.route.ip_route_interface_list.delete()
    device.ios__ip.route.vrf.delete()
    device.ios__ip.ssh.server.algorithm.encryption.delete()
    device.ios__logging.host.ipv4_vrf.delete()
    device.ios__logging.host.ipv4.delete()
    device.ios__logging.source_interface.delete()
    device.ios__ntp.peer.peer_list.delete()
    device.ios__ntp.server.peer_list.delete()
    device.ios__ntp.server.vrf.delete()
    device.ios__ntp.peer.vrf.delete()
    device.ios__ntp.authentication_key.delete()
    device.ios__ntp.trusted_key.delete()
    device.ios__router.bgp.delete()
    device.ios__router.ospf.delete()

