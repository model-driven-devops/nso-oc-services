# -*- mode: python; python-indent: 4 -*-
from translation.common import is_oc_routing_policy_configured
from translation.openconfig_xe.xe_acls import xe_acls_interfaces_program_service
from translation.openconfig_xe.xe_acls import xe_acls_lines_program_service
from translation.openconfig_xe.xe_acls import xe_acls_ntp_program_service
from translation.openconfig_xe.xe_acls import xe_acls_program_service
from translation.openconfig_xe.xe_interfaces import xe_interfaces_program_service
from translation.openconfig_xe.xe_network_instances import xe_network_instances_program_service
from translation.openconfig_xe.xe_routing_policy import xe_routing_policy_program_service
from translation.openconfig_xe.xe_system import xe_system_program_service
from translation.openconfig_xe.xe_stp import xe_stp_program_service


def check_xe_features(oc_self) -> None:
    """
    Check the OC - XE features.
    """
    if len(oc_self.service.oc_if__interfaces.interface) > 0:
        xe_interfaces_program_service(oc_self)

    # Spanning-tree
    if oc_self.service.oc_stp__stp.oc_stp__global.config.enabled_protocol.exists():
        xe_stp_program_service(oc_self)
    # OpenConfig ACL
    if len(oc_self.service.oc_acl__acl.acl_sets.acl_set) > 0:
        xe_acls_program_service(oc_self)
    if len(oc_self.service.oc_acl__acl.interfaces.interface) > 0:
        xe_acls_interfaces_program_service(oc_self)
    if len(oc_self.service.oc_acl__acl.oc_acl_ext__lines.line) > 0:
        xe_acls_lines_program_service(oc_self)
    xe_acls_ntp_program_service(oc_self)

    # OpenConfig routing-policy
    if oc_self.service.oc_rpol__routing_policy:
        xe_routing_policy_program_service(oc_self)

    # OpenConfig Network Instances
    if len(oc_self.service.oc_netinst__network_instances.network_instance) > 0:
        xe_network_instances_program_service(oc_self)

    # OpenConfig System
    xe_system_program_service(oc_self)
