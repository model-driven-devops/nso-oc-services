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
