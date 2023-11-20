import ipaddress
from typing import Tuple
import re

def xr_system_get_interface_ip_address(s, nso_props) -> dict:
    """
    Returns a dictionary of
    IPs and interface names, e.g. {'172.16.255.1: 'Loopback0', '192.168.1.1': 'GigabitEthernet0/0/0/1'}
    """
    ip_name_dict = dict()
    device_config = nso_props.root.devices.device[nso_props.device_name].config
    for a in dir(device_config.cisco_ios_xr__interface):
        if not a.startswith('__'):
            class_method = getattr(device_config.cisco_ios_xr__interface, a)
            for i in class_method:
                try:
                    if i.ipv4.address.ip:
                        ip_name_dict[str(i.ipv4.address.ip)] = str(i) + str(i.id)
                except:
                    pass
    s.log.info(f'Device: {nso_props.device_name} ip_name_dict: {ip_name_dict}')
    return ip_name_dict
