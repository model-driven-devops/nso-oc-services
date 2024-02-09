# -*- mode: python; python-indent: 4 -*-
from translation.common import get_interface_type_and_number

dscp_dict = {8:'cs1', 10:'af11', 12:'af12', 14:'af13', 16:'cs2', 18:'af21', 20:'af22',
                22:'af23', 24:'cs3', 26:'af31', 28:'af32', 30:'af33', 32:'cs4', 34:'af41',
                36:'af42', 38:'af43', 40:'cs5', 46:'ef', 48:'cs6', 56:'cs7', 0:'default'}

def xe_qos_program_service(self, nso_props) -> None:
    """
    Program service
    """

    device_cdb = nso_props.root.devices.device[nso_props.device_name].config

    # Forwarding-groups
    """
    Configure forwarding-groups
    """
    for fg in nso_props.service.oc_qos__qos.forwarding_groups.forwarding_group:
        if device_cdb.ios__policy_map.exists(fg.name):
            del device_cdb.ios__policy_map[fg.name]
        device_cdb.ios__policy_map.create(fg.name)

    # Class-map
    """
    Configure classifiers
    """
    list_cmap = []
    for c_map in nso_props.service.oc_qos__qos.classifiers.classifier:
        pmap_cmap = {}
        # Configure class-map
        if device_cdb.ios__class_map.exists(c_map.name) and c_map.name != 'class-default':
            del device_cdb.ios__class_map[c_map.name]
        elif c_map.name == 'class-default':
            for t_map in c_map.terms.term:
                pmap_cmap[t_map.actions.config.target_group] = c_map.name
        else:
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
        list_cmap.append(pmap_cmap)

    # Schedulers
    """
    Configure schedulers
    """
    for sched_pol in nso_props.service.oc_qos__qos.scheduler_policies.scheduler_policy:
        for sequence in sched_pol.schedulers.scheduler:
            # Configure policy-map
            p_map = device_cdb.ios__policy_map.create(sequence.output.config.output_fwd_group)
            for dict_pmap_cmap in list_cmap:
                if p_map.name in dict_pmap_cmap.keys() and dict_pmap_cmap[p_map.name] in sched_pol.name:
                    c_map = dict_pmap_cmap[p_map.name]
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
            for interface in nso_props.service.oc_qos__qos.interfaces.interface:
                if interface.output.scheduler_policy.config.name == sched_pol.name:
                    conf_out_service_policy(device_cdb, interface, sequence)
                elif interface.input.scheduler_policy.config.name == sched_pol.name:
                    conf_in_service_policy(device_cdb, interface, sequence)

def conf_shape_params(device_cdb, sequence, c_map, p_map):

    # Configure class priority
    if sequence.config.priority == 'STRICT':
        class_priority = device_cdb.ios__policy_map[p_map].ios__class[c_map].priority
        if sequence.one_rate_two_color.config.cir_pct:
            class_priority.create()
            class_priority.percent = sequence.one_rate_two_color.config.cir_pct
        elif sequence.one_rate_two_color.config.cir:
            class_priority.create()
            class_priority.kilo_bits = int(sequence.one_rate_two_color.config.cir / 1000)
        if sequence.one_rate_two_color.config.bc:
            class_priority.burst = sequence.one_rate_two_color.config.bc
    # Configure class bandwidth
    else:
        class_bandwidth = device_cdb.ios__policy_map[p_map].ios__class[c_map].bandwidth
        if sequence.one_rate_two_color.config.cir_pct:
            class_bandwidth.percent = sequence.one_rate_two_color.config.cir_pct
        elif sequence.one_rate_two_color.config.cir:
            class_bandwidth.bits = sequence.one_rate_two_color.config.cir
        elif sequence.one_rate_two_color.config.cir_pct_remaining:
            class_bandwidth.remaining.percent.percent = sequence.one_rate_two_color.config.cir_pct_remaining

def conf_police_params(device_cdb, sequence, c_map, p_map):
    
    # Configure policing one-rate-two-color
    if sequence.one_rate_two_color:
        # Configure cir percentage
        if sequence.one_rate_two_color.config.cir_pct:
            police_cir_percent = device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent
            police_cir_percent.percentage = sequence.one_rate_two_color.config.cir_pct
            if sequence.one_rate_two_color.config.bc:
                # TODO convert bytes to ms
                police_cir_percent.bc = sequence.one_rate_two_color.config.bc
                police_cir_percent.bc_ms.ms.create()
            # Configure conform action
            if sequence.one_rate_two_color.conform_action.config.set_dscp:
                dscp = modify_dscp(sequence.one_rate_two_color.conform_action.config.set_dscp)                
                police_cir_percent.actions.conform_set_dscp_transmit.conform_action.set_dscp_transmit = dscp
            # Configure exceed action
            if sequence.one_rate_two_color.exceed_action:
                if sequence.one_rate_two_color.exceed_action.config.set_dscp:
                    dscp = modify_dscp(sequence.one_rate_two_color.exceed_action.config.set_dscp)
                    police_cir_percent.actions.exceed_set_dscp_transmit.exceed_action.set_dscp_transmit = dscp
                elif sequence.one_rate_two_color.exceed_action.config.drop:
                    police_cir_percent.actions.exceed_drop.exceed_action.drop.create()
        # Configure cir
        elif sequence.one_rate_two_color.config.cir:
            police_cir = device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police
            police_cir.cir = sequence.one_rate_two_color.config.cir
            if sequence.one_rate_two_color.config.bc:
                police_cir.bc = sequence.one_rate_two_color.config.bc
            # Configure conform action
            if sequence.one_rate_two_color.conform_action.config.set_dscp:
                dscp = modify_dscp(sequence.one_rate_two_color.conform_action.config.set_dscp)
                police_cir.actions.conform_set_dscp_transmit.conform_action.set_dscp_transmit = dscp
            # Configure exceed action
            if sequence.one_rate_two_color.exceed_action:
                if sequence.one_rate_two_color.exceed_action.config.set_dscp:
                    dscp = modify_dscp(sequence.one_rate_two_color.exceed_action.config.set_dscp)
                    police_cir.actions.exceed_set_dscp_transmit.exceed_action.set_dscp_transmit = dscp
                elif sequence.one_rate_two_color.exceed_action.config.drop:
                    police_cir.actions.exceed_drop.exceed_action.drop.create()
    # Configure policing two-rate-three-color
    if sequence.two_rate_three_color:
        # Configure cir percentage
        if sequence.two_rate_three_color.config.cir_pct:
            police_cir_percent = device_cdb.ios__policy_map[p_map].ios__class[c_map].police_cir_percent.police.cir.percent
            police_cir_percent.percentage = sequence.two_rate_three_color.config.cir_pct
            if sequence.two_rate_three_color.config.bc:
                # TODO convert bytes to ms
                police_cir_percent.bc = sequence.two_rate_three_color.config.bc
                police_cir_percent.bc_ms.ms.create()
            if sequence.two_rate_three_color.config.pir_pct:
                police_cir_percent.pir.percent = sequence.two_rate_three_color.config.pir_pct
                if sequence.two_rate_three_color.config.be:
                    # TODO convert bytes to ms
                    police_cir_percent.pir_be.be = sequence.two_rate_three_color.config.be
                    police_cir_percent.pir_be_ms.ms.create()
            # Configure conform action
            if sequence.two_rate_three_color.conform_action.config.set_dscp:
                dscp = modify_dscp(sequence.two_rate_three_color.conform_action.config.set_dscp)
                police_cir_percent.actions.conform_set_dscp_transmit.conform_action.set_dscp_transmit = dscp
            # Configure exceed action
            if sequence.two_rate_three_color.exceed_action:
                if sequence.two_rate_three_color.exceed_action.config.set_dscp:
                    dscp = modify_dscp(sequence.two_rate_three_color.exceed_action.config.set_dscp)
                    police_cir_percent.actions.exceed_set_dscp_transmit.exceed_action.set_dscp_transmit = dscp
                elif sequence.two_rate_three_color.exceed_action.config.drop:
                    police_cir_percent.actions.exceed_drop.exceed_action.drop.create()
            # Configure violate action
            if sequence.two_rate_three_color.violate_action:
                if sequence.two_rate_three_color.violate_action.config.set_dscp:
                    dscp = modify_dscp(sequence.two_rate_three_color.violate_action.config.set_dscp)
                    police_cir_percent.actions.violate_set_dscp_transmit.violate_action.set_dscp_transmit = dscp
                elif sequence.two_rate_three_color.violate_action.config.drop:
                    police_cir_percent.actions.violate_drop.violate_action.drop.create()
        # Configure cir
        elif sequence.two_rate_three_color.config.cir:
            police_cir = device_cdb.ios__policy_map[p_map].ios__class[c_map].police_policy_map.police
            police_cir.cir = sequence.two_rate_three_color.config.cir
            if sequence.two_rate_three_color.config.bc:
                police_cir.bc = sequence.two_rate_three_color.config.bc
            if sequence.two_rate_three_color.config.pir:
                police_cir.pir = sequence.two_rate_three_color.config.pir
                if sequence.two_rate_three_color.config.be:
                    police_cir.pir_be.be = sequence.two_rate_three_color.config.be
            # Configure conform action
            if sequence.two_rate_three_color.conform_action.config.set_dscp:
                dscp = modify_dscp(sequence.two_rate_three_color.conform_action.config.set_dscp)
                police_cir.actions.conform_set_dscp_transmit.conform_action.set_dscp_transmit = dscp
            # Configure exceed action
            if sequence.two_rate_three_color.exceed_action:
                if sequence.two_rate_three_color.exceed_action.config.set_dscp:
                    dscp = modify_dscp(sequence.two_rate_three_color.exceed_action.config.set_dscp)
                    police_cir.actions.exceed_set_dscp_transmit.exceed_action.set_dscp_transmit = dscp
                elif sequence.two_rate_three_color.exceed_action.config.drop:
                    police_cir.actions.exceed_drop.exceed_action.drop.create()
            # Configure violate action
            if sequence.two_rate_three_color.violate_action:
                if sequence.two_rate_three_color.violate_action.config.set_dscp:
                    dscp = modify_dscp(sequence.two_rate_three_color.violate_action.config.set_dscp)
                    police_cir.actions.violate_set_dscp_transmit.violate_action.set_dscp_transmit = dscp
                elif sequence.two_rate_three_color.exceed_action.config.drop:
                    police_cir.actions.violate_drop.violate_action.drop.create()

def conf_out_service_policy(device_cdb, interface, sequence):
    
    interface_type, interface_number = get_interface_type_and_number(interface.config.interface_id)

    # Configure service-policy output
    device_int = device_cdb.ios__interface
    if interface_type == 'GigabitEthernet':
        device_int.GigabitEthernet.create(interface_number)
        device_int.GigabitEthernet[interface_number].service_policy.output = sequence.output.config.output_fwd_group
    elif interface_type == 'Port_channel':
        device_int.Port_channel.create(interface_number)
        device_int.Port_channel[interface_number].service_policy.output = sequence.output.config.output_fwd_group
    elif interface_type == 'Loopback':
        device_int.Loopback.create(interface_number)
        if sequence.one_rate_two_color.config.queuing_behavior == 'POLICE' or sequence.two_rate_three_color:
            device_int.Loopback[interface_number].service_policy.output = sequence.output.config.output_fwd_group
    elif interface_type == 'Tunnel':
        device_int.Tunnel.create(interface_number)
        device_int.Tunnel[interface_number].service_policy.output = sequence.output.config.output_fwd_group
    else:
        raise ValueError(
            f'Interface type {interface_type} not supported by this NSO_OC_Services implementation. Please file an issue at https://github.com/model-driven-devops/nso-oc-services')

def conf_in_service_policy(device_cdb, interface, sequence):

    interface_type, interface_number = get_interface_type_and_number(interface.config.interface_id)

    # Configure service-policy-input
    device_int = device_cdb.ios__interface
    if interface_type == 'GigabitEthernet':
        device_int.GigabitEthernet.create(interface_number)
        if sequence.one_rate_two_color.config.queuing_behavior == 'POLICE' or sequence.two_rate_three_color:
            device_int.GigabitEthernet[interface_number].service_policy.input = sequence.output.config.output_fwd_group
    elif interface_type == 'Port_channel':
        device_int.Port_channel.create(interface_number)
        device_int.Port_channel[interface_number].service_policy.input = sequence.output.config.output_fwd_group
    elif interface_type == 'Loopback':
        device_int.Loopback.create(interface_number)
        if sequence.one_rate_two_color.config.queuing_behavior == 'POLICE' or sequence.two_rate_three_color:
            device_int.Loopback[interface_number].service_policy.input = sequence.output.config.output_fwd_group
    elif interface_type == 'Tunnel':
        device_int.Tunnel.create(interface_number)
        if sequence.one_rate_two_color.config.queuing_behavior == 'POLICE' or sequence.two_rate_three_color:
            device_int.Tunnel[interface_number].service_policy.input = sequence.output.config.output_fwd_group
    else:
        raise ValueError(
            f'Interface type {interface_type} not supported by this NSO_OC_Services implementation. Please file an issue at https://github.com/model-driven-devops/nso-oc-services')

def modify_dscp(dscp):
    if (dscp % 2) != 0:
        return dscp
    return dscp_dict.get(dscp, 'default')