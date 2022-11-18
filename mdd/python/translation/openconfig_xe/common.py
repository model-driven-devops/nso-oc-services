import ipaddress
from typing import Tuple
import re

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
