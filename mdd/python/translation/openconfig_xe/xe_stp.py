# -*- mode: python; python-indent: 4 -*-

import ncs
from translation.openconfig_xe.common import xe_get_interface_type_and_number


def xe_stp_program_service(self) -> None:
    """
    Program service for xe NED features.
    """
    xe_stp_global(self)
    if len(self.service.oc_stp__stp.interfaces.interface) > 0:
        xe_stp_interfaces(self)
    stp_version_handler[self.service.oc_stp__stp.oc_stp__global.config.enabled_protocol.as_list()[0]]["handler"](self)


def config_vlan_stp_timers(service_vlan, device_cdb) -> None:
    if not device_cdb.vlan.vlan_list.exists(service_vlan.vlan_id):
        device_cdb.vlan.vlan_list.create(service_vlan.vlan_id)
    vlan_cdb = device_cdb.vlan.vlan_list[service_vlan.vlan_id]
    if service_vlan.config.forwarding_delay:
        vlan_cdb.forward_time = service_vlan.config.forwarding_delay
    if service_vlan.config.hello_time:
        vlan_cdb.hello_time = service_vlan.config.hello_time
    if service_vlan.config.hold_count:
        raise ValueError("XE NED cisco-ios-cli-6.85 does not support spanning-tree hold-count")
    if service_vlan.config.max_age:
        vlan_cdb.max_age = service_vlan.config.max_age
    if service_vlan.config.bridge_priority:
        vlan_cdb.priority = service_vlan.config.bridge_priority


def get_pvst_vlan_interfaces(service_vlan) -> list:
    """
    Return a dictionary of VLAN ID to list of interfaces
    Interface list contains tuples of interface name, port cost, and port priority
    """
    interface_list = []
    for interface in service_vlan.interfaces.interface:
        interface_data = (interface.config.name,
                          interface.config.cost,
                          interface.config.port_priority)
        interface_list.append(interface_data)
    interface_list.sort()
    return interface_list


def check_stp_xpvst_vlan_interface_values(xpvst_vlan_interfaces) -> None:
    """
    Since the XE interface STP cost and port priorities are defined on the interface, if the cost or port priority
    is changed, it must be changed under all VLANs.
    """
    if len(xpvst_vlan_interfaces) == 1:
        pass
    else:
        for vlan in xpvst_vlan_interfaces[1:]:
            if xpvst_vlan_interfaces[0] != vlan:
                raise ValueError("For IOS XE, spanning-tree interface cost and port-priorities must be the same under all VLANs.")


def process_xpvst_interfaces(self, if_list: list) -> None:
    for interface in if_list:
        """
        interface[0] = interface name
        interface[1] = interface cost
        interface[2] = interface port_priority
        """
        interface_type, interface_number = xe_get_interface_type_and_number(interface[0])
        class_attribute = getattr(self.root.devices.device[self.device_name].config.ios__interface,
                                  interface_type)
        stp_interface = class_attribute[interface_number]
        if interface[1]:
            stp_interface.spanning_tree.cost = interface[1]
        if interface[2]:
            stp_interface.spanning_tree.port_priority = interface[2]


def xe_stp_rpvst(self) -> None:
    """
    RPVST configuration
    """
    if len(self.service.oc_stp__stp.rapid_pvst.vlan) > 0:
        device_cdb = self.root.devices.device[self.device_name].config.ios__spanning_tree
        rpvst_vlan_interfaces = []
        for service_vlan in self.service.oc_stp__stp.rapid_pvst.vlan:
            config_vlan_stp_timers(service_vlan, device_cdb)
            rpvst_vlan_interfaces.append(get_pvst_vlan_interfaces(service_vlan))
        # XE doesn't allow STP cost and port priorities different per VLAN
        # Verify if interfaces are listed in VLANs, that they are in all VLANs and contain the same values
        check_stp_xpvst_vlan_interface_values(rpvst_vlan_interfaces)
        if len(rpvst_vlan_interfaces) > 0:
            process_xpvst_interfaces(self, rpvst_vlan_interfaces[0])


def xe_stp_pvst(self) -> None:
    """
    PVST configuration
    """
    device_cdb = self.root.devices.device[self.device_name].config.ios__spanning_tree
    # Uplinkfast
    if self.service.oc_stp__stp.oc_stp__global.config.uplinkfast:
        device_cdb.uplinkfast.create()
    elif self.service.oc_stp__stp.oc_stp__global.config.uplinkfast is False and device_cdb.uplinkfast.exists():
            device_cdb.uplinkfast.delete()
    # Backbonefast
    if self.service.oc_stp__stp.oc_stp__global.config.backbonefast:
        device_cdb.backbonefast.create()
    elif self.service.oc_stp__stp.oc_stp__global.config.backbonefast is False and device_cdb.backbonefast.exists():
            device_cdb.backbonefast.delete()
    if len(self.service.oc_stp__stp.oc_stp_ext__pvst.vlan) > 0:
        pvst_vlan_interfaces = []
        for service_vlan in self.service.oc_stp__stp.oc_stp_ext__pvst.vlan:
            config_vlan_stp_timers(service_vlan, device_cdb)
            pvst_vlan_interfaces.append(get_pvst_vlan_interfaces(service_vlan))
        # XE doesn't allow STP cost and port priorities different per VLAN
        # Verify if interfaces are listed in VLANs, that they are in all VLANs and contain the same values
        check_stp_xpvst_vlan_interface_values(pvst_vlan_interfaces)
        if len(pvst_vlan_interfaces) > 0:
            process_xpvst_interfaces(self, pvst_vlan_interfaces[0])


def xe_stp_mstp(self) -> None:
    """
    MSTP configuration
    """
    self.log.info("\nxe_stp_mstp\n")
    if len(self.service.oc_stp__stp.mstp.mstp_instances) > 0:
        device_cdb = self.root.devices.device[self.device_name].config.ios__spanning_tree
        if self.service.oc_stp__stp.mstp.config.name:
            device_cdb.mst.configuration.name = self.service.oc_stp__stp.mstp.config.name
        if self.service.oc_stp__stp.mstp.config.revision:
            device_cdb.mst.configuration.revision = self.service.oc_stp__stp.mstp.config.revision
        if self.service.oc_stp__stp.mstp.config.max_hop:
            raise ValueError("XE NED cisco-ios-cli-6.85 does not support multiple spanning-tree max-hop")
        if self.service.oc_stp__stp.mstp.config.hello_time:
            raise ValueError("XE NED cisco-ios-cli-6.85 does not support multiple spanning-tree hello-time")
        if self.service.oc_stp__stp.mstp.config.max_age:
            raise ValueError("XE NED cisco-ios-cli-6.85 does not support multiple spanning-tree max-age")
        if self.service.oc_stp__stp.mstp.config.forwarding_delay:
            device_cdb.forward_time = self.service.oc_stp__stp.mstp.config.forwarding_delay
        if self.service.oc_stp__stp.mstp.config.hold_count:
            raise ValueError("XE NED cisco-ios-cli-6.85 does not support multiple spanning-tree hold-count")


stp_version_handler = {
        "PVST": {"type": "pvst", "handler": xe_stp_pvst},
        "MSTP": {"type": "mst", "handler": xe_stp_mstp},
        "RAPID_PVST": {"type": "rapid-pvst", "handler": xe_stp_rpvst}
    }


def xe_stp_global(self) -> None:
    """
    STP global configuration
    """
    device_cdb = self.root.devices.device[self.device_name].config.ios__spanning_tree
    # STP mode
    if len(self.service.oc_stp__stp.oc_stp__global.config.enabled_protocol.as_list()) > 1:
        raise ValueError(
            f"XE devices support running only one version of STP at a time. Your OpenConfig is trying to configure {len(self.service.oc_stp__stp.oc_stp__global.config.enabled_protocol.as_list())}.")
    if not stp_version_handler.get(self.service.oc_stp__stp.oc_stp__global.config.enabled_protocol.as_list()[0], False):
        raise ValueError(
            f"STP mode {self.service.oc_stp__stp.oc_stp__global.config.enabled_protocol.as_list()[0]} is not implemented at this time.")
    else:
        device_cdb.mode = stp_version_handler.get(
            self.service.oc_stp__stp.oc_stp__global.config.enabled_protocol.as_list()[0]).get("type")

    # Bridge assurance
    if self.service.oc_stp__stp.oc_stp__global.config.bridge_assurance:
        raise ValueError(
            f"STP bridge assurance is not implemented at this time.")
    # Loopguard
    if self.service.oc_stp__stp.oc_stp__global.config.loop_guard:
        device_cdb.loopguard.default.create()
    elif self.service.oc_stp__stp.oc_stp__global.config.loop_guard is False and device_cdb.loopguard.default.exists():
        device_cdb.loopguard.default.delete()
    # Etherchannel-misconfig-guard
    if self.service.oc_stp__stp.oc_stp__global.config.etherchannel_misconfig_guard:
        device_cdb.etherchannel.guard.misconfig.create()
    elif self.service.oc_stp__stp.oc_stp__global.config.etherchannel_misconfig_guard is False and device_cdb.etherchannel.guard.misconfig.exists():
        device_cdb.etherchannel.guard.misconfig.delete()
    # BPDU guard
    if self.service.oc_stp__stp.oc_stp__global.config.bpdu_guard:
        device_cdb.portfast.edge.bpduguard.default.create()
    elif self.service.oc_stp__stp.oc_stp__global.config.bpdu_guard is False and device_cdb.portfast.edge.bpduguard.default.exists():
        device_cdb.portfast.edge.bpduguard.default.delete()
    # BPDU filter
    if self.service.oc_stp__stp.oc_stp__global.config.bpdu_filter:
        device_cdb.portfast.edge.bpdufilter.default.create()
    elif self.service.oc_stp__stp.oc_stp__global.config.bpdu_filter is False and device_cdb.portfast.edge.bpdufilter.default.exists():
        device_cdb.portfast.edge.bpdufilter.default.delete()


def get_l2vlan_interfaces(self) -> dict:
    """
    Check all interfaces for TRUNK or ACCESS status
    Return dict of interface names to modes, i.e. {"GigabitEthernet1/0": "TRUNK", "GigabitEthernet1/1": "ACCESS"}
    """
    service_l2vlan_interfaces = {}
    for interface in self.service.oc_if__interfaces.interface:
        if interface.config.type == "ianaift:l2vlan" or (
                interface.config.type == "ianaift:ethernetCsmacd" and interface.ethernet.config.aggregate_id) or (
                interface.config.type == "ianaift:ieee8023adLag" and len(interface.subinterfaces.subinterface) == 0):
            if interface.config.type == "ianaift:l2vlan" or (
                    interface.config.type == "ianaift:ethernetCsmacd" and interface.ethernet.config.aggregate_id and interface.ethernet.switched_vlan.config.interface_mode):
                service_l2vlan_interfaces[interface.name] = str(interface.ethernet.switched_vlan.config.interface_mode)
            elif interface.config.type == "ianaift:ieee8023adLag" and len(interface.subinterfaces.subinterface) == 0 and interface.aggregation.switched_vlan.config.interface_mode:
                service_l2vlan_interfaces[interface.name] = str(interface.aggregation.switched_vlan.config.interface_mode)
    return service_l2vlan_interfaces


def xe_stp_interfaces(self) -> None:
    """
    STP interface configuration
    """
    service_l2vlan_interfaces = get_l2vlan_interfaces(self)
    stp_edge_auto_flag = False
    for service_interface in self.service.oc_stp__stp.interfaces.interface:
        interface_type, interface_number = xe_get_interface_type_and_number(service_interface.config.name)
        class_attribute = getattr(self.root.devices.device[self.device_name].config.ios__interface, interface_type)
        physical_interface_cdb = class_attribute[interface_number]
        # Guard - Root or Loop
        if service_interface.config.guard == "ROOT":
            physical_interface_cdb.spanning_tree.guard = "root"
        elif service_interface.config.guard == "LOOP":
            physical_interface_cdb.spanning_tree.guard = "loop"
        elif service_interface.config.guard == "NONE":
            physical_interface_cdb.spanning_tree.guard = "none"
        # BPDU Guard
        if service_interface.config.bpdu_guard:
            physical_interface_cdb.spanning_tree.bpduguard.enable.create()
        elif service_interface.config.bpdu_guard is False and physical_interface_cdb.spanning_tree.bpduguard.enable.exists():
            physical_interface_cdb.spanning_tree.bpduguard.enable.delete()
        # BPDU filter
        if service_interface.config.bpdu_filter:
            physical_interface_cdb.spanning_tree.bpdufilter = "enable"
        elif service_interface.config.bpdu_filter is False:
            physical_interface_cdb.spanning_tree.bpdufilter = "disable"
        # Link type
        if service_interface.config.link_type == "P2P":
            physical_interface_cdb.spanning_tree.link_type = "point-to-point"
        elif service_interface.config.link_type == "SHARED":
            physical_interface_cdb.spanning_tree.link_type = "shared"
        # Edge-port (portfast)
        if service_interface.config.edge_port == "oc-stp-types:EDGE_AUTO":
            stp_edge_auto_flag = True
            if service_l2vlan_interfaces.get(service_interface.config.name) == "TRUNK":
                raise ValueError(
                    "Spanning-tree Protocol EDGE_AUTO is not supported on TRUNK interfaces. If desired, configure EDGE_ENABLE instead")
            if physical_interface_cdb.spanning_tree.portfast.trunk.exists():
                physical_interface_cdb.spanning_tree.portfast.trunk.delete()
            if physical_interface_cdb.spanning_tree.portfast.disable.exists():
                physical_interface_cdb.spanning_tree.portfast.disable.delete()
            if physical_interface_cdb.spanning_tree.portfast.exists():
                physical_interface_cdb.spanning_tree.portfast.delete()
        elif service_interface.config.edge_port == "oc-stp-types:EDGE_ENABLE":
            if physical_interface_cdb.spanning_tree.portfast.disable.exists():
                physical_interface_cdb.spanning_tree.portfast.disable.delete()
            if service_l2vlan_interfaces.get(service_interface.config.name) == "ACCESS":
                physical_interface_cdb.spanning_tree.portfast.create()
            elif service_l2vlan_interfaces.get(service_interface.config.name) == "TRUNK":
                physical_interface_cdb.spanning_tree.portfast.create()
                physical_interface_cdb.spanning_tree.portfast.trunk.create()
        elif service_interface.config.edge_port == "oc-stp-types:EDGE_DISABLE":
            physical_interface_cdb.spanning_tree.portfast.create()
            physical_interface_cdb.spanning_tree.portfast.disable.create()
        if not service_interface.config.edge_port:
            if physical_interface_cdb.spanning_tree.portfast.trunk.exists():
                physical_interface_cdb.spanning_tree.portfast.trunk.delete()
            if physical_interface_cdb.spanning_tree.portfast.disable.exists():
                physical_interface_cdb.spanning_tree.portfast.disable.delete()
            if physical_interface_cdb.spanning_tree.portfast.exists():
                physical_interface_cdb.spanning_tree.portfast.delete()

    # ENABLE STP Portfast default is using STP EDGE_AUTO interface configurations
    if stp_edge_auto_flag:
        self.root.devices.device[self.device_name].config.ios__spanning_tree.portfast.edge.default.create()
