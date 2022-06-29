"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_configuration.json, save the NSO device
configuration minus parts replaced by OpenConfig to a file named {device_name}_configuration_remaining.json,
and save the MDD OpenConfig configuration to a file named {nso_device}_openconfig.json.

The script requires the following environment variables:
NSO_HOST - IP address or hostname for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation
TEST - True or False. True enables sending the OpenConfig to the NSO server after generation

This file can also be imported as a module and run using the main() function.
"""
import copy
import json
import os
import urllib3


openconfig_system = {
    "openconfig-system:system": {
        "openconfig-system:aaa": {},
        "openconfig-system:clock": {},
        "openconfig-system:config": {},
        "openconfig-system:dns": {},
        "openconfig-system:logging": {},
        "openconfig-system:ntp": {
            "openconfig-system:config": {},
            "openconfig-system:ntp-keys": {
                "openconfig-system:ntp-key": []},
            "openconfig-system:servers": {
                "openconfig-system:server": []}
        },
        "openconfig-system:ssh-server": {"openconfig-system:config": {}},
        "openconfig-system:telnet-server": {}
    }
}


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
        for number in config_before["tailf-ned-cisco-ios:interface"][if_type]:
            if number.get("ip", {}).get("address", {}).get("primary", {}).get("address"):
                temp_dict.update({f"{if_type}{number['name']}": f"{number.get('ip', {}).get('address', {}).get('primary', {}).get('address')}"})
        interface_ip_name.update(temp_dict)
    return interface_ip_name


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
    body = json.dumps(oc_config)
    oc_result = req.request("PATCH", url, headers=headers, body=body)
    print(f"This is the test_nso_program_oc return code: {oc_result.status}")
    if oc_result.status != 204:
        raise Exception("Error in input payload reported by NSO")


def xe_system_config():
    openconfig_system_config = openconfig_system["openconfig-system:system"]["openconfig-system:config"]

    openconfig_system_config["openconfig-system:hostname"] = config_before_dict["tailf-ned-cisco-ios:hostname"]
    del configs_leftover["tailf-ned-cisco-ios:hostname"]

    if config_before_dict.get("tailf-ned-cisco-ios:banner", {}).get("login"):
        openconfig_system_config["openconfig-system:login-banner"] = config_before_dict.get("tailf-ned-cisco-ios:banner", {}).get("login")
        del configs_leftover["tailf-ned-cisco-ios:banner"]["login"]

    if config_before_dict.get("tailf-ned-cisco-ios:banner", {}).get("motd"):
        openconfig_system_config["openconfig-system:motd-banner"] = config_before_dict.get("tailf-ned-cisco-ios:banner", {}).get("motd")
        del configs_leftover["tailf-ned-cisco-ios:banner"]["motd"]

    if config_before_dict.get("tailf-ned-cisco-ios:ip", {}).get("domain", {}).get("name"):
        openconfig_system_config["openconfig-system:domain-name"] = config_before_dict.get("tailf-ned-cisco-ios:ip", {}).get("domain", {}).get("name")
        del configs_leftover["tailf-ned-cisco-ios:ip"]["domain"]["name"]

    if config_before_dict.get("tailf-ned-cisco-ios:ip", {}).get("options", {}).get("drop"):
        openconfig_system_config["openconfig-system-ext:ip-options"] = "DROP"
        del configs_leftover["tailf-ned-cisco-ios:ip"]["options"]

    if config_before_dict.get("tailf-ned-cisco-ios:ip", {}).get("options", {}).get("ignore"):
        openconfig_system_config["openconfig-system-ext:ip-options"] = "IGNORE"
        del configs_leftover["tailf-ned-cisco-ios:ip"]["options"]

    if (config_before_dict.get("tailf-ned-cisco-ios:enable", {}).get("secret", {}).get("secret")) and \
            (config_before_dict.get("tailf-ned-cisco-ios:enable", {}).get("secret", {}).get("type") == "0"):
        openconfig_system_config["openconfig-system-ext:enable-secret"] = config_before_dict.get("tailf-ned-cisco-ios:enable", {}).get("secret", {}).get("secret")
        del configs_leftover["tailf-ned-cisco-ios:enable"]

    if config_before_dict["tailf-ned-cisco-ios:line"]["console"][0].get("exec-timeout"):
        seconds = config_before_dict["tailf-ned-cisco-ios:line"]["console"][0]["exec-timeout"].get("minutes", 0) * 60
        seconds += config_before_dict["tailf-ned-cisco-ios:line"]["console"][0]["exec-timeout"].get("seconds", 0)
        openconfig_system_config["openconfig-system-ext:console-exec-timeout-seconds"] = seconds
        del configs_leftover["tailf-ned-cisco-ios:line"]["console"][0]["exec-timeout"]


def xe_system_ssh_server():
    openconfig_system_ssh_server_config = openconfig_system["openconfig-system:system"]["openconfig-system:ssh-server"]["openconfig-system:config"]

    if config_before_dict.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("time-out"):
        openconfig_system_ssh_server_config["openconfig-system-ext:ssh-timeout"] = config_before_dict.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("time-out")
        del configs_leftover["tailf-ned-cisco-ios:ip"]["ssh"]["time-out"]

    if config_before_dict.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("version"):
        if config_before_dict.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("version") == 1:
            openconfig_system_ssh_server_config["openconfig-system:protocol-version"] = "V1"
        elif config_before_dict.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("version") == 2:
            openconfig_system_ssh_server_config["openconfig-system:protocol-version"] = "V2"
        del configs_leftover["tailf-ned-cisco-ios:ip"]["ssh"]["version"]
    else:
        openconfig_system_ssh_server_config["openconfig-system:protocol-version"] = "V1_V2"

    if config_before_dict.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("source-interface"):
        for i, n in config_before_dict["tailf-ned-cisco-ios:ip"]["ssh"]["source-interface"].items():
            openconfig_system_ssh_server_config["openconfig-system-ext:ssh-source-interface"] = f"{i}{n}"
        del configs_leftover["tailf-ned-cisco-ios:ip"]["ssh"]["source-interface"]

    if config_before_dict["tailf-ned-cisco-ios:line"]["vty"][0].get("exec-timeout"):
        seconds = config_before_dict["tailf-ned-cisco-ios:line"]["vty"][0]["exec-timeout"].get("minutes", 0) * 60
        seconds += config_before_dict["tailf-ned-cisco-ios:line"]["vty"][0]["exec-timeout"].get("seconds", 0)
        openconfig_system_ssh_server_config["timeout"] = seconds
        del configs_leftover["tailf-ned-cisco-ios:line"]["vty"][0]["exec-timeout"]

    if config_before_dict["tailf-ned-cisco-ios:line"]["vty"][0].get("absolute-timeout"):
        openconfig_system_ssh_server_config["openconfig-system-ext:absolute-timeout-minutes"] = config_before_dict["tailf-ned-cisco-ios:line"]["vty"][0]["absolute-timeout"]
        del configs_leftover["tailf-ned-cisco-ios:line"]["vty"][0]["absolute-timeout"]

    if config_before_dict["tailf-ned-cisco-ios:line"]["vty"][0].get("session-limit"):
        openconfig_system_ssh_server_config["session-limit"] = config_before_dict["tailf-ned-cisco-ios:line"]["vty"][0].get("session-limit")
        del configs_leftover["tailf-ned-cisco-ios:line"]["vty"][0]["session-limit"]


def xe_system_ntp():
    openconfig_system_ntp = openconfig_system["openconfig-system:system"]["openconfig-system:ntp"]

    if config_before_dict.get("tailf-ned-cisco-ios:ntp", {}).get("authenticate"):
        openconfig_system_ntp["openconfig-system:config"]["openconfig-system:enable-ntp-auth"] = True
        del configs_leftover["tailf-ned-cisco-ios:ntp"]["authenticate"]

    if config_before_dict.get("tailf-ned-cisco-ios:ntp", {}).get("logging"):
        openconfig_system_ntp["openconfig-system:config"]["openconfig-system-ext:ntp-enable-logging"] = True
        del configs_leftover["tailf-ned-cisco-ios:ntp"]["logging"]

    if config_before_dict.get("tailf-ned-cisco-ios:ntp", {}).get("source"):
        for i, n in config_before_dict.get("tailf-ned-cisco-ios:ntp", {}).get("source").items():
            source_interface = f"{i}{n}"
        source_interface_ip = interface_ip_name_dict.get(source_interface)
        openconfig_system_ntp["openconfig-system:config"]["ntp-source-address"] = source_interface_ip
        del configs_leftover["tailf-ned-cisco-ios:ntp"]["source"]

    if config_before_dict.get("tailf-ned-cisco-ios:ntp", {}).get("trusted-key") and config_before_dict.get("tailf-ned-cisco-ios:ntp", {}).get("authentication-key"):
        trusted_key_numbers = [x["key-number"] for x in config_before_dict.get("tailf-ned-cisco-ios:ntp", {}).get("trusted-key")]
        for auth_key in config_before_dict.get("tailf-ned-cisco-ios:ntp", {}).get("authentication-key"):
            if auth_key["number"] in trusted_key_numbers and auth_key.get("md5"):
                key_dict = {"openconfig-system:key-id": auth_key["number"],
                            "openconfig-system:config": {"openconfig-system:key-id": auth_key["number"],
                                                         "openconfig-system:key-type": "NTP_AUTH_MD5",
                                                         "openconfig-system:key-value": auth_key.get("md5").get("secret")}
                            }
                openconfig_system_ntp["openconfig-system:ntp-keys"]["openconfig-system:ntp-key"].append(key_dict)

                configs_leftover["tailf-ned-cisco-ios:ntp"]["authentication-key"].remove(auth_key)
                configs_leftover["tailf-ned-cisco-ios:ntp"]["trusted-key"].remove({"key-number": auth_key["number"]})


nso_host = os.environ.get("NSO_HOST")
nso_username = os.environ.get("NSO_USERNAME", "ubuntu")
nso_password = os.environ.get("NSO_PASSWORD", "admin")
nso_device = os.environ.get("NSO_DEVICE", "xe1")
test = os.environ.get("TEST", "False")

config_before_dict = nso_get_device_config(nso_host, nso_username, nso_password, nso_device)
configs_leftover = copy.deepcopy(config_before_dict)
interface_ip_name_dict = xe_system_get_interface_ip_address(config_before_dict)


def main():
    """
    Translates NSO Device configurations to MDD OpenConfig configurations.

    Requires environment variables:
    NSO_HOST: str
    NSO_USERNAME: str
    NSO_PASSWORD: str
    NSO_DEVICE: str
    TEST - If True, sends generated OC configuration to NSO Server: str

    NSO configuration, MDD OpenConfig configuration, and NSO remaining configuration files are saved in the working dir.
    """
    xe_system_config()
    xe_system_ssh_server()
    xe_system_ntp()

    mdd_openconfig = {"mdd:openconfig": openconfig_system }

    print(json.dumps(config_before_dict, indent=4))
    print(json.dumps(configs_leftover, indent=4))
    print(json.dumps(mdd_openconfig, indent=4))

    with open(f"{nso_device}_configuration.json", "w") as b:
        b.write(json.dumps(config_before_dict, indent=4))
    with open(f"{nso_device}_configuration_remaining.json", "w") as a:
        a.write(json.dumps(configs_leftover, indent=4))
    with open(f"{nso_device}_openconfig.json", "w") as o:
        o.write(json.dumps(openconfig_system, indent=4))

    if test == 'True':
        test_nso_program_oc(nso_host, nso_username, nso_password, nso_device, mdd_openconfig)


if __name__ == '__main__':
    main()
