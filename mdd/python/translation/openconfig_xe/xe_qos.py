# -*- mode: python; python-indent: 4 -*-
from translation.openconfig_xe.common import xe_system_get_interface_ip_address
from translation.common import get_interface_type_and_number

def xe_qos_program_service(self, nso_props) -> None:
    """
    Program service
    """

    device_cdb = nso_props.root.devices.device[nso_props.device_name].config
    # pmap_cmap = {}

    # Forwarding-groups
    """
    Configure forwarding-groups
    """
    # self.log.info(f'0*** len classifier {len(nso_props.service.oc_qos__qos.classifiers.classifier)}\n\n')
    if len(nso_props.service.oc_qos__qos.forwarding_groups.forwarding_group) > 0:
        for fg in nso_props.service.oc_qos__qos.forwarding_groups.forwarding_group:
            device_cdb.ios__policy_map.create(fg.name)

    # Class-map
    """
    Configure class-maps
    """
    if len(nso_props.service.oc_qos__qos.classifiers.classifier) > 0:
        pmap_cmap = {}
        for c_map in nso_props.service.oc_qos__qos.classifiers.classifier:
            device_cdb.ios__class_map.create(c_map.name)
            for t_map in c_map.terms.term:
                pmap_cmap[t_map.actions.config.target_group] = c_map.name
                self.log.info(f'0*** pmap_cmap {pmap_cmap}\n\n')
                if t_map.conditions.ipv4.config.protocol == 4:
                    if t_map.conditions.ipv4.config.dscp_set:
                        for match_ip_dscp in t_map.conditions.ipv4.config.dscp_set:
                            device_cdb.ios__class_map[c_map.name].prematch = 'match-all'
                            device_cdb.ios__class_map[c_map.name].match.ip.dscp.create(match_ip_dscp)
                    elif t_map.conditions.ipv4.config.dscp:
                        device_cdb.ios__class_map[c_map.name].prematch = 'match-all'
                        device_cdb.ios__class_map[c_map.name].match.ip.dscp.create(
                            t_map.conditions.ipv4.config.dscp)
                else:
                    if t_map.conditions.ipv4.config.dscp_set:
                        for match_dscp in t_map.conditions.ipv4.config.dscp_set:
                            device_cdb.ios__class_map[c_map.name].prematch = 'match-all'
                            device_cdb.ios__class_map[c_map.name].match.dscp.create(match_dscp)
                    elif t_map.conditions.ipv4.config.dscp:
                        device_cdb.ios__class_map[c_map.name].prematch = 'match-all'
                        device_cdb.ios__class_map[c_map.name].match.dscp.create(
                            t_map.conditions.ipv4.config.dscp)

    # Schedulers
    """
    Configure schedulers
    """
    if len(nso_props.service.oc_qos__qos.scheduler_policies.scheduler_policy) > 0:
        for sched_pol in nso_props.service.oc_qos__qos.scheduler_policies.scheduler_policy:
            if len(sched_pol.schedulers.scheduler) > 0:
                for sequence in sched_pol.schedulers.scheduler:
                    p_map = device_cdb.ios__policy_map.create(sequence.output.config.output_fwd_group)
                    if pmap_cmap:
                        if p_map.name in pmap_cmap.keys():
                            c_map = pmap_cmap[p_map.name]
                            device_cdb.ios__policy_map[p_map.name].ios__class.create(c_map)
                            self.log.info(f'1*** sequence.config.type = {sequence.config.type}\n\n')
                            if sequence.config.type == 'oc-qos-types:ONE_RATE_TWO_COLOR':
                                if sequence.one_rate_two_color.config.queuing_behavior == 'SHAPE':
                                    conf_shape_params(self, device_cdb, sequence, c_map, p_map.name)
                                elif sequence.one_rate_two_color.config.queuing_behavior == 'POLICE':
                                    self.log.info(f'2*** queuing_behavior = {sequence.one_rate_two_color.config.queuing_behavior}\n\n')
                                    conf_police_params(self, device_cdb, sequence, c_map, p_map.name)

def conf_shape_params(self, device_cdb, sequence, c_map, p_map):

    if sequence.config.priority == 'STRICT':
        if sequence.one_rate_two_color.config.cir_pct:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].priority.create()
            device_cdb.ios__policy_map[p_map].ios__class[c_map].priority.percent = sequence.one_rate_two_color.config.cir_pct
        if sequence.one_rate_two_color.config.cir:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].priority.create()
            # TODO: fix kilo_bits
            device_cdb.ios__policy_map[p_map].ios__class[c_map].priority.kilo_bits = sequence.one_rate_two_color.config.cir
    else:
        if sequence.one_rate_two_color.config.cir_pct:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].bandwidth.percent = sequence.one_rate_two_color.config.cir_pct
        if sequence.one_rate_two_color.config.cir:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].bandwidth.bits = sequence.one_rate_two_color.config.cir

def conf_police_params(self, device_cdb, sequence, c_map, p_map):
    
    if sequence.one_rate_two_color.config.cir_pct:
        self.log.info(f'8*** cir_pct = {sequence.one_rate_two_color.config.cir_pct}\n\n')
        device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.percentage = sequence.one_rate_two_color.config.cir_pct
        if sequence.one_rate_two_color.config.bc:
            self.log.info(f'9*** bc = {sequence.one_rate_two_color.config.bc}\n\n')
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.bc = sequence.one_rate_two_color.config.bc
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.bc_ms.ms.create()
        if sequence.one_rate_two_color.conform_action.config.set_dscp:
            self.log.info(f'10*** conform dscp = {sequence.one_rate_two_color.conform_action.config.set_dscp}\n\n')
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.actions.conform_set_dscp_transmit.conform_action.set_dscp_transmit = sequence.one_rate_two_color.conform_action.config.set_dscp
        if sequence.one_rate_two_color.exceed_action.config.set_dscp:
            self.log.info(f'11*** exceed dscp = {sequence.one_rate_two_color.exceed_action.config.set_dscp}\n\n')
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.actions.exceed_set_dscp_transmit.exceed_action.set_dscp_transmit = sequence.one_rate_two_color.exceed_action.config.set_dscp
        if sequence.one_rate_two_color.exceed_action.config.drop:
            self.log.info(f'12*** exceed drop = {sequence.one_rate_two_color.exceed_action.config.drop}\n\n')
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.actions.exceed_drop.exceed_action.drop.create()

    else:
        if sequence.one_rate_two_color.config.cir:
            self.log.info(f'3*** cir = {sequence.one_rate_two_color.config.cir}\n\n')
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.cir = sequence.one_rate_two_color.config.cir
        if sequence.one_rate_two_color.config.bc:
            self.log.info(f'4*** bc = {sequence.one_rate_two_color.config.bc}\n\n')
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.bc = sequence.one_rate_two_color.config.bc
        if sequence.one_rate_two_color.conform_action.config.set_dscp:
            self.log.info(f'5*** conform dscp = {sequence.one_rate_two_color.conform_action.config.set_dscp}\n\n')
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.actions.conform_set_dscp_transmit.conform_action.set_dscp_transmit = sequence.one_rate_two_color.conform_action.config.set_dscp
        if sequence.one_rate_two_color.exceed_action.config.set_dscp:
            self.log.info(f'6*** exceed dscp = {sequence.one_rate_two_color.exceed_action.config.set_dscp}\n\n')
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.actions.exceed_set_dscp_transmit.exceed_action.set_dscp_transmit = sequence.one_rate_two_color.exceed_action.config.set_dscp
        if sequence.one_rate_two_color.exceed_action.config.drop:
            self.log.info(f'7*** exceed drop = {sequence.one_rate_two_color.exceed_action.config.drop}\n\n')
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.actions.exceed_drop.exceed_action.drop.create()


