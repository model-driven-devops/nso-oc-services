# -*- mode: python; python-indent: 4 -*-
from translation.common import is_oc_routing_policy_configured
from translation.openconfig_xr.xr_system import xr_system_program_service
from translation.openconfig_xr.xr_interfaces import xr_interfaces_program_service
from translation.openconfig_xr.xr_acls import xr_acls_program_service
from translation.openconfig_xr.xr_acls import xr_acls_interfaces_program_service
from translation.openconfig_xr.xr_acls import xr_acls_lines_program_service
from translation.openconfig_xr.xr_acls import xr_acls_ntp_program_service
from translation.openconfig_xr.xr_network_instances import xr_network_instances_program_service


def check_xr_features(oc_self, nso_props) -> None:
    """
    Check the OC - XR features.
    """
    # OpenConfig Interfaces
    if len(nso_props.service.oc_if__interfaces.interface) > 0:
        xr_interfaces_program_service(oc_self, nso_props)
    # Spanning-tree
    if nso_props.service.oc_stp__stp.oc_stp__global.config.enabled_protocol.exists():
        raise NotImplementedError('openconfig-stp has not yet been implemented for XR')
    # # OpenConfig ACL
    if len(nso_props.service.oc_acl__acl.acl_sets.acl_set) > 0:
        xr_acls_program_service(oc_self, nso_props)
    if len(nso_props.service.oc_acl__acl.interfaces.interface) > 0:
        xr_acls_interfaces_program_service(oc_self, nso_props)
    if len(nso_props.service.oc_acl__acl.oc_acl_ext__lines.line) > 0:
        xr_acls_lines_program_service(oc_self, nso_props)
    if (nso_props.service.oc_acl__acl.oc_acl_ext__ntp.server.config.server_acl_set or
        nso_props.service.oc_acl__acl.oc_acl_ext__ntp.peer.config.peer_acl_set):
        xr_acls_ntp_program_service(oc_self, nso_props)

    # OpenConfig routing-policy
    if is_oc_routing_policy_configured(nso_props):
        raise NotImplementedError('openconfig-routing-policy has not yet been implemented for XR')

    # OpenConfig Network Instances
    if len(nso_props.service.oc_netinst__network_instances.network_instance) > 0:
        xr_network_instances_program_service(oc_self, nso_props)

    # OpenConfig System
    xr_system_program_service(oc_self, nso_props)
