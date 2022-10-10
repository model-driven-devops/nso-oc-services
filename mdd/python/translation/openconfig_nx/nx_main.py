# -*- mode: python; python-indent: 4 -*-
from translation.common import is_oc_routing_policy_configured
from translation.openconfig_nx.nx_system import nx_system_program_service

def check_nx_features(self) -> None:
    """
    Check the OC - NX features.
    """
    # OpenConfig Interfaces
    if len(self.service.oc_if__interfaces.interface) > 0:
        raise NotImplementedError('openconfig-interfaces has not yet been implemented for NX')

    # # OpenConfig ACL
    if len(self.service.oc_acl__acl.acl_sets.acl_set) > 0:
        raise NotImplementedError('openconfig-acl-sets has not yet been implemented for NX')
    if len(self.service.oc_acl__acl.interfaces.interface) > 0:
        raise NotImplementedError('openconfig-acl-interfaces has not yet been implemented for NX')
    if len(self.service.oc_acl__acl.oc_acl_ext__lines.line) > 0:
        raise NotImplementedError('openconfig-acl-lines has not yet been implemented for NX')
    if (self.service.oc_acl__acl.oc_acl_ext__ntp.server.config.server_acl_set or
        self.service.oc_acl__acl.oc_acl_ext__ntp.peer.config.peer_acl_set):
        raise NotImplementedError('openconfig-acl-ntp has not yet been implemented for NX')

    # OpenConfig routing-policy
    if is_oc_routing_policy_configured(self):
        raise NotImplementedError('openconfig-routing-policy has not yet been implemented for NX')

    # OpenConfig Network Instances
    if len(self.service.oc_netinst__network_instances.network_instance) > 0:
        raise NotImplementedError('openconfig-network-distances has not yet been implemented for NX')

    # OpenConfig System
    nx_system_program_service(self)
