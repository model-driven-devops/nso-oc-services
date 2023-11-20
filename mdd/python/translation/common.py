from typing import Tuple
import re
import ipaddress

class NsoProps:
    """
    Holds the NSO service, root, and proplist attributes.
    :param service: NSO ListElement
    :param root: NSO root
    :param proplist: list of tuples containing template variable to value
    """
    def __init__(self, service, root, proplist, device_name) -> None:
        self.service = service
        self.root = root
        self.proplist = proplist
        self.device_name = device_name

def is_oc_routing_policy_configured(nso_props):
    if (len(nso_props.service.oc_rpol__routing_policy.defined_sets.prefix_sets.prefix_set) > 0 or
        len(nso_props.service.oc_rpol__routing_policy.defined_sets.bgp_defined_sets.as_path_sets.as_path_set) > 0 or
        len(nso_props.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.community_sets.community_set) > 0 or
        len(nso_props.service.oc_rpol__routing_policy.defined_sets.oc_bgp_pol__bgp_defined_sets.ext_community_sets.ext_community_set) > 0 or
        len(nso_props.service.oc_rpol__routing_policy.policy_definitions.policy_definition) > 0):
        return True
    
    return False

def get_interface_type_and_number(interface: str) -> Tuple[str, str]:
    """
    Receive full interface name. Returns interface type and number.
    :param interface: full interface name
    :return: tuple of interface type, interface number
    """
    rt = re.search(r'\D+', interface)
    interface_name = rt.group(0)
    rn = re.search(r'[0-9]+(\/[0-9]+)*', interface)
    interface_number = rn.group(0)
    interface_number = interface_number.replace("{", "").replace("}", "")
    interface_name = interface_name.replace('-', '_')
    
    return interface_name, interface_number

def get_interface_type_number_and_subinterface(interface: str) -> Tuple[str, str]:
    """
    Receive full interface name. Returns interface type and number.
    :param interface: full interface name
    :return: tuple of interface type, interface number.subinterface number
    """
    rt = re.search(r'\D+', interface)
    interface_name = rt.group(0)
    rn = re.search(r'[0-9]+(\/[0-9]+)*(\.[0-9]+)*', interface)
    interface_number = rn.group(0)
    interface_number = interface_number.replace("{", "").replace("}", "")
    return interface_name, interface_number

def prefix_to_network_and_mask(prefix: str) -> str:
    """
    Turns a network prefix into a network_id and wildcard-mask
    :param prefix: str
    :return: 'network_id wildcard_mask': str
    """
    network = ipaddress.ip_network(prefix)
    
    return f'{str(network.network_address)} {str(network.hostmask)}'


def verify_ipv4(ip: str) -> bool:
    """
    Takes in a string, return true if IP address or False if not
    :param ip:
    :return bool:
    """
    try:
        if type(ipaddress.ip_address(ip)) is ipaddress.IPv4Address:
            return True
        else:
            return False
    except ValueError:
        return False
