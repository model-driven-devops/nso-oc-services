#! /usr/bin/env python3
import json
import urllib3


def nso_get_device_config(host: str, username: str, password: str, device: str) -> dict:
    """
    Get device configuration from NSO. Return configuration as python dict.
    :param host: IP or hostname: str
    :param username: str
    :param password: str
    :param device: str
    :return: NSO Device configuration
    """
    url = f"http://{host}:8080/restconf/data/tailf-ncs:devices/device={device}/config"
    req = urllib3.PoolManager()
    headers = urllib3.make_headers(basic_auth=f"{username}:{password}")
    headers.update({"Content-Type": "application/yang-data+json",
                    "Accept": "application/yang-data+json"})
    configuration_result = req.request("GET", url, headers=headers)
    config_before_string = configuration_result.data.decode()
    return json.loads(config_before_string)["tailf-ncs:config"]


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
        else:
            for number in config_before["tailf-ned-cisco-ios:interface"][if_type]:
                if number.get("ip", {}).get("address", {}).get("primary", {}).get("address"):
                    temp_dict.update({f"{if_type}{number['name']}": f"{number.get('ip', {}).get('address', {}).get('primary', {}).get('address')}"})
            interface_ip_name.update(temp_dict)
    return interface_ip_name


def test_nso_program_oc(host: str, username: str, password: str, device: str, oc_config: dict) -> None:
    """
    Send translated Openconfig device configuration to NSO
    :param host: str
    :param username: str
    :param password: str
    :param device: str
    :param oc_config: dict
    :return: None
    """
    url = f"http://{host}:8080/restconf/data/tailf-ncs:devices/device={device}/mdd:openconfig"
    req = urllib3.PoolManager()
    headers = urllib3.make_headers(basic_auth=f"{username}:{password}")
    headers.update({"Content-Type": "application/yang-data+json",
                    "Accept": "application/yang-data+json"})
    oc = {"mdd:openconfig": {}}
    oc["mdd:openconfig"].update(oc_config)
    body = json.dumps(oc)
    oc_result = req.request("PATCH", url, headers=headers, body=body)
    if oc_result.status != 204:
        raise Exception("Error in input payload reported by NSO")