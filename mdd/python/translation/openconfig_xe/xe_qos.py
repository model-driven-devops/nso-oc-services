# -*- mode: python; python-indent: 4 -*-
from translation.openconfig_xe.common import xe_system_get_interface_ip_address
from translation.common import get_interface_type_and_number

def xe_qos_program_service(self, nso_props) -> None:
    """
    Program service
    """

    device_cdb = nso_props.root.devices.device[nso_props.device_name].config

    # Forwarding-groups
    """
    Configure forwarding-groups
    """
    if len(nso_props.service.oc_qos__qos.forwarding_groups.forwarding_group) > 0:
        for fg in nso_props.service.oc_qos__qos.forwarding_groups.forwarding_group:
            device_cdb.ios__policy_map.create(fg.name)
    elif len(nso_props.service.oc_qos__qos.forwarding_groups.forwarding_group) == 0:
        if device_cdb.ios__policy_map:
            device_cdb.ios__policy_map.delete()

    # Class-map
    """
    Configure classifiers
    """
    if len(nso_props.service.oc_qos__qos.classifiers.classifier) > 0:
        pmap_cmap = {}
        for c_map in nso_props.service.oc_qos__qos.classifiers.classifier:
            # Configure class-map
            device_cdb.ios__class_map.create(c_map.name)
            for t_map in c_map.terms.term:
                pmap_cmap[t_map.actions.config.target_group] = c_map.name
                # Configure "match ip dscp"
                if t_map.conditions.ipv4.config.protocol == 4:
                    # Configure multiple dscp statements
                    if t_map.conditions.ipv4.config.dscp_set:
                        for new_ip_dscp in t_map.conditions.ipv4.config.dscp_set:
                            new_ip_dscp = modify_dscp(new_ip_dscp)
                            device_cdb.ios__class_map[c_map.name].prematch = 'match-all'
                            device_cdb.ios__class_map[c_map.name].match.ip.dscp.create(new_ip_dscp)
                    # Configure single dscp statements
                    elif t_map.conditions.ipv4.config.dscp:
                        new_ip_dscp = modify_dscp(t_map.conditions.ipv4.config.dscp)
                        device_cdb.ios__class_map[c_map.name].prematch = 'match-all'
                        device_cdb.ios__class_map[c_map.name].match.ip.dscp.create(
                            new_ip_dscp)
                # Configure "match dscp"
                else:
                    # Configure multiple dscp statements
                    if t_map.conditions.ipv4.config.dscp_set:
                        for new_dscp in t_map.conditions.ipv4.config.dscp_set:
                            new_dscp = modify_dscp(new_dscp)
                            device_cdb.ios__class_map[c_map.name].prematch = 'match-all'
                            device_cdb.ios__class_map[c_map.name].match.dscp.create(new_dscp)
                    # Configure single dscp statements
                    elif t_map.conditions.ipv4.config.dscp:
                        new_dscp = modify_dscp(t_map.conditions.ipv4.config.dscp)
                        device_cdb.ios__class_map[c_map.name].prematch = 'match-all'
                        device_cdb.ios__class_map[c_map.name].match.dscp.create(
                            new_dscp)
    elif len(nso_props.service.oc_qos__qos.classifiers.classifier) == 0:
        if device_cdb.ios__class_map:
            device_cdb.ios__class_map.delete()

    # Schedulers
    """
    Configure schedulers
    """
    if len(nso_props.service.oc_qos__qos.scheduler_policies.scheduler_policy) > 0:
        for sched_pol in nso_props.service.oc_qos__qos.scheduler_policies.scheduler_policy:
            if len(sched_pol.schedulers.scheduler) > 0:
                for sequence in sched_pol.schedulers.scheduler:
                    # Configure policy-map
                    p_map = device_cdb.ios__policy_map.create(sequence.output.config.output_fwd_group)
                    if pmap_cmap:
                        if p_map.name in pmap_cmap.keys():
                            c_map = pmap_cmap[p_map.name]
                            # Configure policy-map <policy-map name> class-map <class-map name>
                            device_cdb.ios__policy_map[p_map.name].ios__class.create(c_map)
                            if sequence.config.type == 'oc-qos-types:ONE_RATE_TWO_COLOR':
                                if sequence.one_rate_two_color.config.queuing_behavior == 'SHAPE':
                                    conf_shape_params(device_cdb, sequence, c_map, p_map.name)
                                elif sequence.one_rate_two_color.config.queuing_behavior == 'POLICE':
                                    conf_police_params(device_cdb, sequence, c_map, p_map.name)
                            elif sequence.config.type == 'oc-qos-types:TWO_RATE_THREE_COLOR':
                                    conf_police_params(device_cdb, sequence, c_map, p_map.name)

                    # Interfaces
                    """
                    Configure interfaces
                    """
                    if len(nso_props.service.oc_qos__qos.interfaces.interface) > 0:
                        for interface in nso_props.service.oc_qos__qos.interfaces.interface:
                            if interface.output.scheduler_policy.config.name == sched_pol.name:
                                conf_out_service_policy(device_cdb, interface, sequence)
                            elif interface.input.scheduler_policy.config.name == sched_pol.name:
                                conf_in_service_policy(device_cdb, interface, sequence)

def conf_shape_params(device_cdb, sequence, c_map, p_map):

    # Configure class priority
    if sequence.config.priority == 'STRICT':
        if sequence.one_rate_two_color.config.cir_pct:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].priority.create()
            device_cdb.ios__policy_map[p_map].ios__class[c_map].priority.percent = sequence.one_rate_two_color.config.cir_pct
        elif sequence.one_rate_two_color.config.cir:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].priority.create()
            device_cdb.ios__policy_map[p_map].ios__class[c_map].priority.kilo_bits = int(sequence.one_rate_two_color.config.cir / 1000)
        if sequence.one_rate_two_color.config.bc:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].priority.burst = sequence.one_rate_two_color.config.bc
    # Configure class bandwidth
    else:
        if sequence.one_rate_two_color.config.cir_pct:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].bandwidth.percent = sequence.one_rate_two_color.config.cir_pct
        elif sequence.one_rate_two_color.config.cir:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].bandwidth.bits = sequence.one_rate_two_color.config.cir
        elif sequence.one_rate_two_color.config.cir_pct_remaining:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].bandwidth.remaining.percent.percent = sequence.one_rate_two_color.config.cir_pct_remaining

def conf_police_params(device_cdb, sequence, c_map, p_map):
    
    # Configure policing one-rate-two-color
    if sequence.one_rate_two_color:
        # Configure cir percentage
        if sequence.one_rate_two_color.config.cir_pct:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.percentage = sequence.one_rate_two_color.config.cir_pct
            if sequence.one_rate_two_color.config.bc:
                # TODO convert bytes to ms
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.bc = sequence.one_rate_two_color.config.bc
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.bc_ms.ms.create()
            # Configure conform action
            if sequence.one_rate_two_color.conform_action.config.set_dscp:
                dscp = modify_dscp(sequence.one_rate_two_color.conform_action.config.set_dscp)                
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.actions.conform_set_dscp_transmit.conform_action.set_dscp_transmit = dscp
            # Configure exceed action
            if sequence.one_rate_two_color.exceed_action:
                if sequence.one_rate_two_color.exceed_action.config.set_dscp:
                    dscp = modify_dscp(sequence.one_rate_two_color.exceed_action.config.set_dscp)
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.actions.exceed_set_dscp_transmit.exceed_action.set_dscp_transmit = dscp
                elif sequence.one_rate_two_color.exceed_action.config.drop:
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.actions.exceed_drop.exceed_action.drop.create()
        # Configure cir
        elif sequence.one_rate_two_color.config.cir:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.cir = sequence.one_rate_two_color.config.cir
            if sequence.one_rate_two_color.config.bc:
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.bc = sequence.one_rate_two_color.config.bc
            # Configure conform action
            if sequence.one_rate_two_color.conform_action.config.set_dscp:
                dscp = modify_dscp(sequence.one_rate_two_color.conform_action.config.set_dscp)
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.actions.conform_set_dscp_transmit.conform_action.set_dscp_transmit = dscp
            # Configure exceed action
            if sequence.one_rate_two_color.exceed_action:
                if sequence.one_rate_two_color.exceed_action.config.set_dscp:
                    dscp = modify_dscp(sequence.one_rate_two_color.exceed_action.config.set_dscp)
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.actions.exceed_set_dscp_transmit.exceed_action.set_dscp_transmit = dscp
                elif sequence.one_rate_two_color.exceed_action.config.drop:
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.actions.exceed_drop.exceed_action.drop.create()
    # Configure policing two-rate-three-color
    if sequence.two_rate_three_color:
        # Configure cir percentage
        if sequence.two_rate_three_color.config.cir_pct:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.percentage = sequence.two_rate_three_color.config.cir_pct
            if sequence.two_rate_three_color.config.bc:
                # TODO convert bytes to ms
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.bc = sequence.two_rate_three_color.config.bc
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.bc_ms.ms.create()
            if sequence.two_rate_three_color.config.pir_pct:
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.pir.percent = sequence.two_rate_three_color.config.pir_pct
                if sequence.two_rate_three_color.config.be:
                    # TODO convert bytes to ms
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.pir_be.be = sequence.two_rate_three_color.config.be
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.pir_be_ms.ms.create()
            # Configure conform action
            if sequence.two_rate_three_color.conform_action.config.set_dscp:
                dscp = modify_dscp(sequence.two_rate_three_color.conform_action.config.set_dscp)
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.actions.conform_set_dscp_transmit.conform_action.set_dscp_transmit = dscp
            # Configure exceed action
            if sequence.two_rate_three_color.exceed_action:
                if sequence.two_rate_three_color.exceed_action.config.set_dscp:
                    dscp = modify_dscp(sequence.two_rate_three_color.exceed_action.config.set_dscp)
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.actions.exceed_set_dscp_transmit.exceed_action.set_dscp_transmit = dscp
                elif sequence.two_rate_three_color.exceed_action.config.drop:
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.actions.exceed_drop.exceed_action.drop.create()
            # Configure violate action
            if sequence.two_rate_three_color.violate_action:
                if sequence.two_rate_three_color.violate_action.config.set_dscp:
                    dscp = modify_dscp(sequence.two_rate_three_color.violate_action.config.set_dscp)
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.actions.violate_set_dscp_transmit.violate_action.set_dscp_transmit = dscp
                elif sequence.two_rate_three_color.violate_action.config.drop:
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent.actions.violate_drop.violate_action.drop.create()
        # Configure cir
        elif sequence.two_rate_three_color.config.cir:
            device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.cir = sequence.two_rate_three_color.config.cir
            if sequence.two_rate_three_color.config.bc:
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.bc = sequence.two_rate_three_color.config.bc
            if sequence.two_rate_three_color.config.pir:
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.pir = sequence.two_rate_three_color.config.pir
                if sequence.two_rate_three_color.config.be:
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.pir_be.be = sequence.two_rate_three_color.config.be
            # Configure conform action
            if sequence.two_rate_three_color.conform_action.config.set_dscp:
                dscp = modify_dscp(sequence.two_rate_three_color.conform_action.config.set_dscp)
                device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.actions.conform_set_dscp_transmit.conform_action.set_dscp_transmit = dscp
            # Configure exceed action
            if sequence.two_rate_three_color.exceed_action:
                if sequence.two_rate_three_color.exceed_action.config.set_dscp:
                    dscp = modify_dscp(sequence.two_rate_three_color.exceed_action.config.set_dscp)
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.actions.exceed_set_dscp_transmit.exceed_action.set_dscp_transmit = dscp
                elif sequence.two_rate_three_color.exceed_action.config.drop:
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.actions.exceed_drop.exceed_action.drop.create()
            # Configure violate action
            if sequence.two_rate_three_color.violate_action:
                if sequence.two_rate_three_color.violate_action.config.set_dscp:
                    dscp = modify_dscp(sequence.two_rate_three_color.violate_action.config.set_dscp)
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.actions.violate_set_dscp_transmit.violate_action.set_dscp_transmit = dscp
                elif sequence.two_rate_three_color.exceed_action.config.drop:
                    device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police.actions.violate_drop.violate_action.drop.create()

def conf_out_service_policy(device_cdb, interface, sequence):
    
    interface_type, interface_number = get_interface_type_and_number(interface.config.interface_id)

    # Configure service-policy output
    if interface_type == 'GigabitEthernet':
        device_cdb.ios__interface.GigabitEthernet.create(interface_number)
        device_cdb.ios__interface.GigabitEthernet[interface_number].service_policy.output = sequence.output.config.output_fwd_group
    elif interface_type == 'Port_channel':
        device_cdb.ios__interface.Port_channel.create(interface_number)
        device_cdb.ios__interface.Port_channel[interface_number].service_policy.output = sequence.output.config.output_fwd_group
    elif interface_type == 'Loopback':
        device_cdb.ios__interface.Loopback.create(interface_number)
        if sequence.one_rate_two_color.config.queuing_behavior == 'POLICE' or sequence.two_rate_three_color:
            device_cdb.ios__interface.Loopback[interface_number].service_policy.output = sequence.output.config.output_fwd_group
    elif interface_type == 'Tunnel':
        device_cdb.ios__interface.Tunnel.create(interface_number)
        device_cdb.ios__interface.Tunnel[interface_number].service_policy.output = sequence.output.config.output_fwd_group
    else:
        raise ValueError(
            f'Interface type {interface_type} not supported by this NSO_OC_Services implementation. Please file an issue at https://github.com/model-driven-devops/nso-oc-services')

def conf_in_service_policy(device_cdb, interface, sequence):

    interface_type, interface_number = get_interface_type_and_number(interface.config.interface_id)

    # Configure service-policy-input
    if interface_type == 'GigabitEthernet':
        device_cdb.ios__interface.GigabitEthernet.create(interface_number)
        if sequence.one_rate_two_color.config.queuing_behavior == 'POLICE' or sequence.two_rate_three_color:
            device_cdb.ios__interface.GigabitEthernet[interface_number].service_policy.input = sequence.output.config.output_fwd_group
    elif interface_type == 'Port_channel':
        device_cdb.ios__interface.Port_channel.create(interface_number)
        device_cdb.ios__interface.Port_channel[interface_number].service_policy.input = sequence.output.config.output_fwd_group
    elif interface_type == 'Loopback':
        device_cdb.ios__interface.Loopback.create(interface_number)
        if sequence.one_rate_two_color.config.queuing_behavior == 'POLICE' or sequence.two_rate_three_color:
            device_cdb.ios__interface.Loopback[interface_number].service_policy.input = sequence.output.config.output_fwd_group
    elif interface_type == 'Tunnel':
        device_cdb.ios__interface.Tunnel.create(interface_number)
        if sequence.one_rate_two_color.config.queuing_behavior == 'POLICE' or sequence.two_rate_three_color:
            device_cdb.ios__interface.Tunnel[interface_number].service_policy.input = sequence.output.config.output_fwd_group
    else:
        raise ValueError(
            f'Interface type {interface_type} not supported by this NSO_OC_Services implementation. Please file an issue at https://github.com/model-driven-devops/nso-oc-services')

def modify_dscp(dscp):
    if (dscp % 2) != 0:
        return dscp
    if dscp == 8:
        new_dscp = 'cs1'
    if dscp == 10:
        new_dscp = 'af11'
    elif dscp == 12:
        new_dscp = 'af12'
    elif dscp == 14:
        new_dscp = 'af13'
    elif dscp == 16:
        new_dscp = 'cs2'
    elif dscp == 18:
        new_dscp = 'af21'
    elif dscp == 20:
        new_dscp = 'af22'
    elif dscp == 22:
        new_dscp = 'af23'
    elif dscp == 24:
        new_dscp = 'cs3'
    elif dscp == 26:
        new_dscp = 'af31'
    elif dscp == 28:
        new_dscp = 'af32'
    elif dscp == 30:
        new_dscp = 'af33'
    elif dscp == 32:
        new_dscp = 'cs4'
    elif dscp == 34:
        new_dscp = 'af41'
    elif dscp == 36:
        new_dscp = 'af42'
    elif dscp == 38:
        new_dscp = 'af43'
    elif dscp == 40:
        new_dscp = 'cs5'
    elif dscp == 46:
        new_dscp = 'ef'
    elif dscp == 48:
        new_dscp = 'cs6'
    elif dscp == 56:
        new_dscp = 'cs7'
    else:
        new_dscp = 'default'
    return new_dscp