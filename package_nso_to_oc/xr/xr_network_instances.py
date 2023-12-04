#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_ned_configuration_network_instances.json,
save the NSO device configuration minus parts replaced by OpenConfig to a file named
{device_name}_ned_configuration_remaining_network_instances.json, and save the MDD OpenConfig configuration to a file
named {nso_device}_openconfig_network_instances.json.

The script requires the following environment variables:
NSO_URL - URL for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation
TEST - True or False. True enables sending the OpenConfig to the NSO server after generation
"""

import sys
from importlib.util import find_spec
import copy

network_instances_notes = []
openconfig_network_instances = {
    "openconfig-network-instance:network-instances": {
        "openconfig-network-instance:network-instance": [
            {
                "openconfig-network-instance:name": "default",
                "openconfig-network-instance:config": {
                    "openconfig-network-instance:name": "default",
                    "openconfig-network-instance:type": "DEFAULT_INSTANCE",
                    "openconfig-network-instance:enabled": "true"
                },
                "openconfig-network-instance:protocols": {"openconfig-network-instance:protocol": []},
                "openconfig-network-instance:interfaces": {"openconfig-network-instance:interface": []}
            }
        ]
    }
}


def generate_list_indexes_to_delete(a_list: list, greatest_length: int) -> list:
    delete_indexes = []
    for i in a_list:
        if len(i) <= greatest_length:
            delete_indexes.append(a_list.index(i))
    delete_indexes.sort(reverse=True)
    return delete_indexes


def xr_network_instances(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XR NED to MDD OpenConfig Network Instances
    """
    if config_before.get("tailf-ned-cisco-ios-xr:vrf", {}).get("vrf-list"):
        for vrf_index, vrf in enumerate(config_before.get("tailf-ned-cisco-ios-xr:vrf", {}).get("vrf-list")):
            if vrf.get("address-family"):
                address_families = []
                for key in vrf.get("address-family").keys():
                    if key == "ipv4":
                        address_families.append("openconfig-types:IPV4")
                    if key == "ipv6":
                        address_families.append("openconfig-types:IPV6")
                temp_vrf = {
                    "openconfig-network-instance:name": vrf["name"],
                    "openconfig-network-instance:config": {
                        "openconfig-network-instance:name": vrf["name"],
                        "openconfig-network-instance:type": "L3VRF",
                        "openconfig-network-instance:enabled": "true",
                        "openconfig-network-instance:enabled-address-families": address_families
                    },
                    "openconfig-network-instance:protocols": {"openconfig-network-instance:protocol": []},
                    "openconfig-network-instance:interfaces": {"openconfig-network-instance:interface": []}
                }
                process_rd_rt(temp_vrf, vrf, vrf_index, config_leftover)
                if vrf.get("description"):
                    temp_vrf["openconfig-network-instance:config"]["openconfig-network-instance:description"] = vrf.get(
                        "description")
                    del config_leftover["tailf-ned-cisco-ios-xr:vrf"]["vrf-list"][vrf_index]["description"]
                del config_leftover["tailf-ned-cisco-ios-xr:vrf"]["vrf-list"][vrf_index]["address-family"]
            openconfig_network_instances["openconfig-network-instance:network-instances"][
                "openconfig-network-instance:network-instance"].append(temp_vrf)
        # Clean up VRF remaining
        indexes_to_remove = generate_list_indexes_to_delete(
            config_leftover.get("tailf-ned-cisco-ios-xr:vrf", {}).get("vrf-list", []), 1)
        if indexes_to_remove:
            for vrf_index in indexes_to_remove:
                del config_leftover["tailf-ned-cisco-ios-xr:vrf"]["vrf-list"][vrf_index]
        if not config_leftover["tailf-ned-cisco-ios-xr:vrf"]["vrf-list"]:
            del config_leftover["tailf-ned-cisco-ios-xr:vrf"]["vrf-list"]
        if len(config_leftover["tailf-ned-cisco-ios-xr:vrf"]) == 0:
            del config_leftover["tailf-ned-cisco-ios-xr:vrf"]
    interfaces_by_vrf = get_interfaces_by_vrf(config_before)
    route_forwarding_list_by_vrf = get_route_forwarding_list_by_vrf(config_before, config_leftover)
    configure_network_instances(config_before, config_leftover, interfaces_by_vrf, route_forwarding_list_by_vrf)

    cleanup_null_static_route_leftovers(config_leftover)


def get_interfaces_by_vrf(config_before):
    interfaces_by_vrf = {}
    interfaces = config_before.get("tailf-ned-cisco-ios-xr:interface", {})
    for interface_type, interface_list in interfaces.items():

        if interface_type.endswith("-subinterface"):
            interface_type = interface_type.replace("-subinterface", "")
            interface_list = interface_list[interface_type]

        for interface in interface_list:
            if (not "ipv4" in interface or not "address" in interface["ipv4"]
                    or not "ip" in interface["ipv4"]["address"]):
                continue

            interface_copy = copy.deepcopy(interface)
            if interface_type == "Bundle-Ether":
                interface_type = "Port-channel"
            interface_copy["type"] = interface_type
            # Ensure we get a string type
            interface_copy["id"] = str(interface_copy["id"])

            if "vrf" in interface_copy:
                vrf_name = interface_copy["vrf"]
            else:
                vrf_name = "default"

            if not vrf_name in interfaces_by_vrf:
                interfaces_by_vrf[vrf_name] = []

            interfaces_by_vrf[vrf_name].append(interface_copy)

    return interfaces_by_vrf


def get_route_forwarding_list_by_vrf(config_before, config_leftover):
    route_forwarding_list_by_vrf = {}

    ip_obj = config_before.get("tailf-ned-cisco-ios-xr:router", {}).get("static", {}).get("address-family", {}).get(
        "ipv4", {}).get("unicast", {})
    route_forwarding_list_by_vrf["default"] = {
        common_xr.IP_FORWARDING_LIST: copy.deepcopy(ip_obj.get(common_xr.IP_FORWARDING_LIST, [])),
        common_xr.INTF_LIST: copy.deepcopy(ip_obj.get(common_xr.INTF_LIST, [])),
        common_xr.IP_INTF_FORWARDING_LIST: copy.deepcopy(ip_obj.get(common_xr.IP_INTF_FORWARDING_LIST, []))
    }
    if ip_obj.get("routes"):
        del config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]["address-family"]["ipv4"]["unicast"]["routes"]
    if ip_obj.get("routes-ip"):
        del config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]["address-family"]["ipv4"]["unicast"]["routes-ip"]
    if ip_obj.get("routes-if"):
        del config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]["address-family"]["ipv4"]["unicast"]["routes-if"]

    ip_obj = config_before.get("tailf-ned-cisco-ios-xr:router", {}).get("static", {}).get("vrf", [])
    for index, vrf in enumerate(ip_obj):
        vrf_static_routes = vrf.get("address-family", {}).get("ipv4", {}).get("unicast", {})
        if vrf.get("address-family", {}).get("ipv4", {}).get("unicast", {}).get("routes"):
            del config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]["vrf"][index]["address-family"]["ipv4"]["unicast"][
                "routes"]
        if vrf.get("address-family", {}).get("ipv4", {}).get("unicast", {}).get("routes-ip"):
            del config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]["vrf"][index]["address-family"]["ipv4"]["unicast"][
                "routes-ip"]
        if vrf.get("address-family", {}).get("ipv4", {}).get("unicast", {}).get("routes-if"):
            del config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]["vrf"][index]["address-family"]["ipv4"]["unicast"][
                "routes-if"]
        route_forwarding_list_by_vrf[vrf["name"]] = {
            "vrf-index": index,
            common_xr.IP_FORWARDING_LIST: copy.deepcopy(vrf_static_routes.get(common_xr.IP_FORWARDING_LIST, [])),
            common_xr.INTF_LIST: copy.deepcopy(vrf_static_routes.get(common_xr.INTF_LIST, [])),
            common_xr.IP_INTF_FORWARDING_LIST: copy.deepcopy(
                vrf_static_routes.get(common_xr.IP_INTF_FORWARDING_LIST, []))
        }

    return route_forwarding_list_by_vrf


def configure_network_instances(config_before, config_leftover, interfaces_by_vrf, route_forwarding_list_by_vrf):

    for net_inst in openconfig_network_instances["openconfig-network-instance:network-instances"][
        "openconfig-network-instance:network-instance"]:
        configure_network_interfaces(net_inst, interfaces_by_vrf)

        if len(route_forwarding_list_by_vrf.get(net_inst["openconfig-network-instance:name"], [])) > 0:
            vrf_forwarding_list = route_forwarding_list_by_vrf.get(net_inst["openconfig-network-instance:name"])

            xr_static_route.configure_xr_static_routes(net_inst, vrf_forwarding_list, config_leftover,
                                                       network_instances_notes)

        if net_inst['openconfig-network-instance:config']['openconfig-network-instance:type'] == "DEFAULT_INSTANCE":
            xr_mpls.configure_xr_mpls(net_inst, config_before, config_leftover, network_instances_notes)


def configure_network_interfaces(net_inst, interfaces_by_vrf):
    for interface in interfaces_by_vrf.get(net_inst["openconfig-network-instance:name"], []):
        name_split = interface["id"].split(".")
        primary_interface = name_split[0]
        new_interface = {
            "openconfig-network-instance:id": interface["type"] + interface["id"],
            "openconfig-network-instance:config": {
                "openconfig-network-instance:id": interface["type"] + interface["id"],
                "openconfig-network-instance:interface": interface["type"] + primary_interface
            }
        }

        if interface["type"] != "tunnel-ip":  # tunnel's don't have sub-interfaces
            subinterface = '0' if len(name_split) == 1 else name_split[1]
            new_interface["openconfig-network-instance:config"][
                "openconfig-network-instance:subinterface"] = subinterface

        net_inst["openconfig-network-instance:interfaces"]["openconfig-network-instance:interface"].append(
            new_interface)


def process_rd_rt(temp_vrf, vrf, vrf_index, config_leftover):
    if "rd" in vrf:
        temp_vrf["openconfig-network-instance:config"][
            "openconfig-network-instance:route-distinguisher"] = vrf["rd"]
        temp_vrf["openconfig-network-instance:config"][
            "openconfig-network-instance-ext:route-targets-import"] = []
        temp_vrf["openconfig-network-instance:config"][
            "openconfig-network-instance-ext:route-targets-export"] = []

        # RD is required to create RTs
        # if "route-target" in vrf:
        #     process_rt(temp_vrf, vrf, "import")
        #     process_rt(temp_vrf, vrf, "export")
        #     del config_leftover["tailf-ned-cisco-ios-xr:vrf"]["vrf-list"][vrf_index]["route-target"]

        del config_leftover["tailf-ned-cisco-ios-xr:vrf"]["vrf-list"][vrf_index]["rd"]

        # IPv4 RT import and export policies
        temp_policies = {
            "openconfig-network-instance:inter-instance-policies": {
                "openconfig-network-instance:apply-policy": {
                    "openconfig-network-instance:config": {
                        "openconfig-network-instance:export-policy": [],
                        "openconfig-network-instance:import-policy": []}}}}
        # if vrf.get("address-family", {}).get("ipv4", {}).get("import", {}).get("ipv4", {}).get("unicast", {}).get(
        #         "map"):
        #     temp_policies["openconfig-network-instance:inter-instance-policies"][
        #         "openconfig-network-instance:apply-policy"]["openconfig-network-instance:config"][
        #         "openconfig-network-instance:import-policy"].append(
        #         vrf.get("address-family", {}).get("ipv4", {}).get("import", {}).get("ipv4", {}).get("unicast", {}).get(
        #             "map"))
        #     del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["address-family"]["ipv4"]["import"]
        # if vrf.get("address-family", {}).get("ipv4", {}).get("export", {}).get("map"):
        #     temp_policies["openconfig-network-instance:inter-instance-policies"][
        #         "openconfig-network-instance:apply-policy"]["openconfig-network-instance:config"][
        #         "openconfig-network-instance:export-policy"].append(
        #         vrf.get("address-family", {}).get("ipv4", {}).get("export", {}).get("map"))
        #     del config_leftover["tailf-ned-cisco-ios:vrf"]["definition"][vrf_index]["address-family"]["ipv4"]["export"]
        if "ipv4" in vrf.get("address-family", {}):
            del config_leftover["tailf-ned-cisco-ios-xr:vrf"]["vrf-list"][vrf_index]["address-family"]["ipv4"]
        temp_vrf.update(temp_policies)
        # TODO IPv6 RT import and export policies


# def process_rt(temp_vrf, vrf, rt_type):
#     for rt in vrf["route-target"].get(rt_type, []):
#         if "asn-ip" in rt:
#             temp_vrf["openconfig-network-instance:config"][
#                 f"openconfig-network-instance-ext:route-targets-{rt_type}"].append(rt["asn-ip"])


def cleanup_statics(static_reference):
    if len(static_reference.get("address-family", {}).get("ipv4", {}).get("unicast", [1, 1])) == 0:
        del static_reference["address-family"]["ipv4"]["unicast"]
    if len(static_reference.get("address-family", {}).get("ipv4", [1])) == 0:
        del static_reference["address-family"]["ipv4"]
    if len(static_reference.get("address-family", [1])) == 0:
        del static_reference["address-family"]


def cleanup_null_static_route_leftovers(config_leftover):
    if len(config_leftover.get("tailf-ned-cisco-ios-xr:router", {}).get("static", {}).get("vrf", [])) > 0:
        for vrf in config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]["vrf"]:
            cleanup_statics(vrf)
        vrfs_keep = []
        for vrf in config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]["vrf"]:
            if len(vrf) > 1:
                vrfs_keep.append(vrf)
        config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]["vrf"] = vrfs_keep
    if len(config_leftover.get("tailf-ned-cisco-ios-xr:router", {}).get("static").get("vrf", [1, 1])) == 0:
        del config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]["vrf"]
    if config_leftover.get("tailf-ned-cisco-ios-xr:router", {}).get("static"):
        cleanup_statics(config_leftover.get("tailf-ned-cisco-ios-xr:router", {}).get("static"))
    if "static" in config_leftover.get("tailf-ned-cisco-ios-xr:router", {}) and len(
            config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]) == 0:
        del config_leftover["tailf-ned-cisco-ios-xr:router"]["static"]


def get_updated_configs(list_leftover):
    updated_static_list = []

    for item in list_leftover:
        if item:
            updated_static_list.append(item)

    return updated_static_list


def main(before: dict, leftover: dict, translation_notes: list = []) -> dict:
    """
    Translates NSO Device configurations to MDD OpenConfig configurations.

    Requires environment variables:
    NSO_URL: str
    NSO_USERNAME: str
    NSO_PASSWORD: str
    NSO_DEVICE: str
    TEST - If True, sends generated OC configuration to NSO Server: str

    :param before: Original NSO Device configuration: dict
    :param leftover: NSO Device configuration minus configs replaced with MDD OC: dict
    :return: MDD Openconfig Network Instances configuration: dict
    """

    xr_network_instances(before, leftover)
    translation_notes += network_instances_notes

    return openconfig_network_instances


if __name__ == "__main__":
    sys.path.append("../../")
    sys.path.append("../../../")

    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xr import common_xr
        from package_nso_to_oc.xr import xr_static_route
        from package_nso_to_oc.xr import xr_mpls
        from package_nso_to_oc import common
    else:
        import common_xr
        import xr_static_route
        import xr_mpls
        import common

    (config_before_dict, config_leftover_dict) = common_xr.init_xr_configs()
    main(config_before_dict, config_leftover_dict)
    config_name = "_network_instances"
    config_remaining_name = "_remaining_network_instances"
    oc_name = "_openconfig_network_instances"
    common.print_and_test_configs(
        "xr1", config_before_dict, config_leftover_dict, openconfig_network_instances,
        config_name, config_remaining_name, oc_name, network_instances_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xr import common_xr
        from package_nso_to_oc.xr import xr_static_route
        from package_nso_to_oc.xr import xr_mpls
        from package_nso_to_oc import common
    else:
        from xr import common_xr
        from xr import xr_static_route
        from xr import xr_mpls
        import common
