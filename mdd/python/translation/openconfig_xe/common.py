import ipaddress
from typing import Tuple
import re


def xe_get_interface_type_and_number(interface: str) -> Tuple[str, str]:
    """
    Receive full interface name. Returns interface type and number.
    :param interface: full interface name
    :return: tuple of interface type, interface number
    """
    rt = re.search(r'\D+', interface)
    interface_name = rt.group(0)
    rn = re.search(r'[0-9]+(\/[0-9]+)*', interface)
    interface_number = rn.group(0)
    interface_name = interface_name.replace('-', '_')
    return interface_name, interface_number


def xe_get_interface_type_number_and_subinterface(interface: str) -> Tuple[str, str]:
    """
    Receive full interface name. Returns interface type and number.
    :param interface: full interface name
    :return: tuple of interface type, interface number.subinterface number
    """
    rt = re.search(r'\D+', interface)
    interface_name = rt.group(0)
    rn = re.search(r'[0-9]+(\/[0-9]+)*(\.[0-9]+)*', interface)
    interface_number = rn.group(0)
    return interface_name, interface_number


def xe_system_get_interface_ip_address(s) -> dict:
    """
    Returns a dictionary of
    IPs and interface names, e.g. {'172.16.255.1: 'Loopback0', '192.168.1.1': 'GigabitEthernet1'}
    """
    ip_name_dict = dict()
    device_config = s.root.devices.device[s.device_name].config
    for a in dir(device_config.ios__interface):
        if not a.startswith('__'):
            class_method = getattr(device_config.ios__interface, a)
            for i in class_method:
                try:
                    if i.ip.address.primary.address:
                        ip_name_dict[str(i.ip.address.primary.address)] = str(i) + str(i.name)
                except:
                    pass
    s.log.info(f'Device: {s.device_name} ip_name_dict: {ip_name_dict}')
    return ip_name_dict


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