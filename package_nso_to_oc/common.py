#! /usr/bin/env python3

import os
import json
import urllib3
import re
import ipaddress
from pathlib import Path, os as path_os
from typing import Tuple


# Different device OS
XE = "xe"
XR = "xr"

# In case Host OS can't resolve port name to number for ACLs
port_name_number_mapping = {"netbios-ss": 139,
                            "non500-isakmp": 4500,
                            "lpd": 515}


def remove_read_only_modules(config_before):
    if config_before.get("ietf-yang-library:yang-library"):
        del config_before["ietf-yang-library:yang-library"]
    if config_before.get("ietf-yang-library:modules-state"):
        del config_before["ietf-yang-library:modules-state"]


def nso_get_device_config(nso_api_url: str, username: str, password: str, device: str) -> dict:
    """
    Get device configuration from NSO. Return configuration as python dict.
    :param nso_api_url: str
    :param username: str
    :param password: str
    :param device: str
    :return: NSO Device configuration
    """
    url = f"{nso_api_url}/restconf/data/tailf-ncs:devices/device={device}/config"
    req = urllib3.PoolManager(cert_reqs='CERT_NONE')
    headers = urllib3.make_headers(basic_auth=f"{username}:{password}")
    headers.update({"Content-Type": "application/yang-data+json",
                    "Accept": "application/yang-data+json"})
    configuration_result = req.request("GET", url, headers=headers)
    config_before_string = configuration_result.data.decode()
    config_before = json.loads(config_before_string)["tailf-ncs:config"]
    remove_read_only_modules(config_before)
    return config_before


def xe_system_get_interface_ip_address(config_before: dict) -> dict:
    """
    Receives an NSO xe configuration and return a dict of interface names to IP addresses.
    E.g, {"GigabitEthernet6": "172.60.1.2"}
    :param config_before: dict
    :return: interface_ip_name dict
    """
    interface_ip_name = {}
    for if_type in config_before["tailf-ned-cisco-ios:interface"]:
        temp_dict = {}
        if if_type == "Port-channel-subinterface":
            for number in config_before["tailf-ned-cisco-ios:interface"]["Port-channel-subinterface"]["Port-channel"]:
                if number.get("ip", {}).get("address", {}).get("primary", {}).get("address"):
                    temp_dict.update({f"Port-channel{number['name']}": f"{number.get('ip', {}).get('address', {}).get('primary', {}).get('address')}"})
            interface_ip_name.update(temp_dict)
        elif if_type == "LISP-subinterface":
            for number in config_before["tailf-ned-cisco-ios:interface"]["LISP-subinterface"]["LISP"]:
                if number.get("ip", {}).get("address", {}).get("primary", {}).get("address"):
                    temp_dict.update({
                                         f"LISP{number['name']}": f"{number.get('ip', {}).get('address', {}).get('primary', {}).get('address')}"})
            interface_ip_name.update(temp_dict)
        else:
            for number in config_before["tailf-ned-cisco-ios:interface"][if_type]:
                if number.get("ip", {}).get("address", {}).get("primary", {}).get("address"):
                    temp_dict.update({f"{if_type}{number['name']}": f"{number.get('ip', {}).get('address', {}).get('primary', {}).get('address')}"})
            interface_ip_name.update(temp_dict)
    return interface_ip_name


def test_nso_program_oc(nso_api_url: str, username: str, password: str, device: str, oc_config: dict) -> None:
    """
    Send translated Openconfig device configuration to NSO
    :param nso_api_url: str
    :param username: str
    :param password: str
    :param device: str
    :param oc_config: dict
    :return: None
    """
    url = f"{nso_api_url}/restconf/data/tailf-ncs:devices/device={device}/mdd:openconfig"
    req = urllib3.PoolManager(cert_reqs='CERT_NONE')
    headers = urllib3.make_headers(basic_auth=f"{username}:{password}")
    headers.update({"Content-Type": "application/yang-data+json",
                    "Accept": "application/yang-data+json"})
    oc = {"mdd:openconfig": {}}
    oc["mdd:openconfig"].update(oc_config)
    body = json.dumps(oc)
    oc_result = req.request("PATCH", url, headers=headers, body=body)
    if oc_result.status != 204:
        if hasattr(oc_result, 'data'):
            raise Exception(f"Error in input payload reported by NSO: {oc_result.data}")
        else:
            raise Exception(f"Error in input payload reported by NSO")

def print_and_test_configs(device_name, config_before_dict, config_leftover_dict, oc, config_name, 
    config_remaining_name, oc_name, translation_notes = []):
    (nso_api_url, nso_username, nso_password) = get_nso_creds()
    nso_device = os.environ.get("NSO_DEVICE", device_name)
    test = os.environ.get("TEST", "False")

    # Determine the project root dir, where we will create our output_data dir (if it doesn't exist).
    # output_data_dir is meant to contain data/config files that we don't want in version control.
    # project_path = str(Path(__file__).resolve().parents[1])
    project_path = os.environ.get("NSO_OC_SERVICES_PATH", os.getcwd()) 
    output_data_dir = f"{project_path}{path_os.sep}output_data{path_os.sep}"
    Path(output_data_dir).mkdir(parents=True, exist_ok=True)

    print(json.dumps(oc, indent=4))
    with open(f"{output_data_dir}{nso_device}{config_name}.json", "w") as b:
        b.write(json.dumps(config_before_dict, indent=4))
    with open(f"{output_data_dir}{nso_device}{config_remaining_name}.json", "w") as a:
        a.write(json.dumps(config_leftover_dict, indent=4))
    with open(f"{output_data_dir}{nso_device}{oc_name}.json", "w") as o:
        o.write(json.dumps(oc, indent=4))

    if len(translation_notes) > 0:
        # Only print to file, if actual notes exist.
        with open(f"{output_data_dir}{nso_device}{config_name}_notes.txt", "w") as o:
            # We run it through a map, just in case an element in our list of notes contain non-string type.
            # Otherwise, we risk an error when joining.
            o.write("\n\n".join(map(lambda note: str(note), translation_notes)))

    if test == "True":
        test_nso_program_oc(nso_api_url, nso_username, nso_password, nso_device, oc["mdd:openconfig"] if "mdd:openconfig" in oc else oc)

def get_nso_creds():
    nso_api_url = os.environ.get("NSO_URL")
    nso_username = os.environ.get("NSO_USERNAME", "ubuntu")
    nso_password = os.environ.get("NSO_PASSWORD", "admin")

    return (nso_api_url, nso_username, nso_password)

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

    return interface_name, interface_number

def get_index_or_default(obj, index, default = {}):
    try:
        return obj[index]
    except:
        return default

def get_interface_number_split(interface_number: str) -> Tuple[int, int]:
    number_split = interface_number.split('.')

    return tuple(number_split) if len(number_split) > 1 else (number_split[0], 0)

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        
        return True
    except ValueError:
        return False
