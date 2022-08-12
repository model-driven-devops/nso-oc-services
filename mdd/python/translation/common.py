def is_oc_routing_policy_configured(oc_self):
    if (len(oc_self.service.oc_rpol__routing_policy.defined_sets.prefix_sets.prefix_set) > 0 or
        len(oc_self.service.oc_rpol__routing_policy.defined_sets.bgp_defined_sets.as_path_sets.as_path_set) > 0 or
        len(oc_self.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.community_sets.community_set) > 0 or
        len(oc_self.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.ext_community_sets.ext_community_set) > 0 or
        len(oc_self.service.oc_rpol__routing_policy.policy_definitions.policy_definition) > 0):
        return True
    
    return False
