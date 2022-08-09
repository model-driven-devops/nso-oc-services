#! /usr/bin/env python3
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
"""
import copy
import json
import os


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


def xe_system_config(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System Config
    """
    openconfig_system_config = openconfig_system["openconfig-system:system"]["openconfig-system:config"]

    openconfig_system_config["openconfig-system:hostname"] = config_before["tailf-ned-cisco-ios:hostname"]
    del config_leftover["tailf-ned-cisco-ios:hostname"]

    if config_before.get("tailf-ned-cisco-ios:banner", {}).get("login"):
        openconfig_system_config["openconfig-system:login-banner"] = config_before.get("tailf-ned-cisco-ios:banner", {}).get("login")
        del config_leftover["tailf-ned-cisco-ios:banner"]["login"]

    if config_before.get("tailf-ned-cisco-ios:banner", {}).get("motd"):
        openconfig_system_config["openconfig-system:motd-banner"] = config_before.get("tailf-ned-cisco-ios:banner", {}).get("motd")
        del config_leftover["tailf-ned-cisco-ios:banner"]["motd"]

    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("domain", {}).get("name"):
        openconfig_system_config["openconfig-system:domain-name"] = config_before.get("tailf-ned-cisco-ios:ip", {}).get("domain", {}).get("name")
        del config_leftover["tailf-ned-cisco-ios:ip"]["domain"]["name"]

    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("options", {}).get("drop"):
        openconfig_system_config["openconfig-system-ext:ip-options"] = "DROP"
        del config_leftover["tailf-ned-cisco-ios:ip"]["options"]

    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("options", {}).get("ignore"):
        openconfig_system_config["openconfig-system-ext:ip-options"] = "IGNORE"
        del config_leftover["tailf-ned-cisco-ios:ip"]["options"]

    if (config_before.get("tailf-ned-cisco-ios:enable", {}).get("secret", {}).get("secret")) and \
            (config_before.get("tailf-ned-cisco-ios:enable", {}).get("secret", {}).get("type") == "0"):
        openconfig_system_config["openconfig-system-ext:enable-secret"] = config_before.get("tailf-ned-cisco-ios:enable", {}).get("secret", {}).get("secret")
        del config_leftover["tailf-ned-cisco-ios:enable"]

    if config_before["tailf-ned-cisco-ios:line"]["console"][0].get("exec-timeout"):
        seconds = config_before["tailf-ned-cisco-ios:line"]["console"][0]["exec-timeout"].get("minutes", 0) * 60
        seconds += config_before["tailf-ned-cisco-ios:line"]["console"][0]["exec-timeout"].get("seconds", 0)
        openconfig_system_config["openconfig-system-ext:console-exec-timeout-seconds"] = seconds
        del config_leftover["tailf-ned-cisco-ios:line"]["console"][0]["exec-timeout"]


def xe_system_ssh_server(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System SSH Server
    """
    openconfig_system_ssh_server_config = openconfig_system["openconfig-system:system"]["openconfig-system:ssh-server"]["openconfig-system:config"]

    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("time-out"):
        openconfig_system_ssh_server_config["openconfig-system-ext:ssh-timeout"] = config_before.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("time-out")
        del config_leftover["tailf-ned-cisco-ios:ip"]["ssh"]["time-out"]

    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("version"):
        if config_before.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("version") == 1:
            openconfig_system_ssh_server_config["openconfig-system:protocol-version"] = "V1"
        elif config_before.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("version") == 2:
            openconfig_system_ssh_server_config["openconfig-system:protocol-version"] = "V2"
        del config_leftover["tailf-ned-cisco-ios:ip"]["ssh"]["version"]
    else:
        openconfig_system_ssh_server_config["openconfig-system:protocol-version"] = "V1_V2"

    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("source-interface"):
        for i, n in config_before["tailf-ned-cisco-ios:ip"]["ssh"]["source-interface"].items():
            openconfig_system_ssh_server_config["openconfig-system-ext:ssh-source-interface"] = f"{i}{n}"
        del config_leftover["tailf-ned-cisco-ios:ip"]["ssh"]["source-interface"]

    if config_before["tailf-ned-cisco-ios:line"]["vty"][0].get("exec-timeout"):
        seconds = config_before["tailf-ned-cisco-ios:line"]["vty"][0]["exec-timeout"].get("minutes", 0) * 60
        seconds += config_before["tailf-ned-cisco-ios:line"]["vty"][0]["exec-timeout"].get("seconds", 0)
        openconfig_system_ssh_server_config["openconfig-system:timeout"] = seconds
        del config_leftover["tailf-ned-cisco-ios:line"]["vty"][0]["exec-timeout"]

    if config_before["tailf-ned-cisco-ios:line"]["vty"][0].get("absolute-timeout"):
        openconfig_system_ssh_server_config["openconfig-system-ext:absolute-timeout-minutes"] = config_before["tailf-ned-cisco-ios:line"]["vty"][0]["absolute-timeout"]
        del config_leftover["tailf-ned-cisco-ios:line"]["vty"][0]["absolute-timeout"]

    if config_before["tailf-ned-cisco-ios:line"]["vty"][0].get("session-limit"):
        openconfig_system_ssh_server_config["session-limit"] = config_before["tailf-ned-cisco-ios:line"]["vty"][0].get("session-limit")
        del config_leftover["tailf-ned-cisco-ios:line"]["vty"][0]["session-limit"]


def xe_add_oc_ntp_server(before_ntp_server_list: list, after_ntp_server_list: list, openconfig_ntp_server_list: list,
                     ntp_type: str, ntp_vrf: str, if_ip: dict) -> None:
    """Generate Openconfig NTP server configurations"""
    for ntp_server_index, ntp_server in enumerate(before_ntp_server_list):
        ntp_server_temp = {"openconfig-system:address": ntp_server["name"],
                           "openconfig-system:config": {
                               "openconfig-system:address": ntp_server["name"],
                               "openconfig-system:association-type": ntp_type,
                               "openconfig-system:port": 123,
                               "openconfig-system:version": 4
                           }}
        # version
        if ntp_server.get("version"):
            ntp_server_temp["openconfig-system:config"]["openconfig-system:version"] = ntp_server.get("version")
            del after_ntp_server_list[ntp_server_index]["version"]
        # iburst
        if type(ntp_server.get("iburst", "")) is list:
            ntp_server_temp["openconfig-system:config"]["openconfig-system:iburst"] = True
            del after_ntp_server_list[ntp_server_index]["iburst"]
        else:
            ntp_server_temp["openconfig-system:config"]["openconfig-system:iburst"] = False
        # prefer
        if type(ntp_server.get("prefer", "")) is list:
            ntp_server_temp["openconfig-system:config"]["openconfig-system:prefer"] = True
            del after_ntp_server_list[ntp_server_index]["prefer"]
        else:
            ntp_server_temp["openconfig-system:config"]["openconfig-system:prefer"] = False
        # authentication key
        if ntp_server.get("key"):
            ntp_server_temp["openconfig-system:config"]["oc-system-ext:ntp-auth-key-id"] = ntp_server.get("key")
            del after_ntp_server_list[ntp_server_index]["key"]
        # source interface
        if ntp_server.get("source"):
            for k, v in ntp_server.get("source").items():
                nso_source_interface = f"{k}{v}"
                ntp_server_temp["openconfig-system:config"]["oc-system-ext:ntp-source-address"] = if_ip.get(
                    nso_source_interface)
                del after_ntp_server_list[ntp_server_index]["source"]
        # vrf
        if ntp_vrf:
            ntp_server_temp["openconfig-system:config"]["oc-system-ext:ntp-use-vrf"] = ntp_vrf

        openconfig_ntp_server_list.append(ntp_server_temp)


def xe_system_ntp(config_before: dict, config_leftover: dict, if_ip: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System NTP
    """
    openconfig_system_ntp = openconfig_system["openconfig-system:system"]["openconfig-system:ntp"]

    if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("authenticate"):
        openconfig_system_ntp["openconfig-system:config"]["openconfig-system:enable-ntp-auth"] = True
        del config_leftover["tailf-ned-cisco-ios:ntp"]["authenticate"]

    if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("logging"):
        openconfig_system_ntp["openconfig-system:config"]["openconfig-system-ext:ntp-enable-logging"] = True
        del config_leftover["tailf-ned-cisco-ios:ntp"]["logging"]

    if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("source"):
        for i, n in config_before.get("tailf-ned-cisco-ios:ntp", {}).get("source").items():
            source_interface = f"{i}{n}"
            source_interface_ip = if_ip.get(source_interface)
            openconfig_system_ntp["openconfig-system:config"]["openconfig-system:ntp-source-address"] = source_interface_ip
        del config_leftover["tailf-ned-cisco-ios:ntp"]["source"]

    if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("trusted-key") and config_before.get(
            "tailf-ned-cisco-ios:ntp", {}).get("authentication-key"):
        trusted_key_numbers = [x["key-number"] for x in
                               config_before.get("tailf-ned-cisco-ios:ntp", {}).get("trusted-key")]
        for auth_key in config_before.get("tailf-ned-cisco-ios:ntp", {}).get("authentication-key"):
            if auth_key["number"] in trusted_key_numbers and auth_key.get("md5"):
                key_dict = {"openconfig-system:key-id": auth_key["number"],
                            "openconfig-system:config": {"openconfig-system:key-id": auth_key["number"],
                                                         "openconfig-system:key-type": "NTP_AUTH_MD5",
                                                         "openconfig-system:key-value": auth_key.get("md5").get(
                                                             "secret")}
                            }
                openconfig_system_ntp["openconfig-system:ntp-keys"]["openconfig-system:ntp-key"].append(key_dict)

                config_leftover["tailf-ned-cisco-ios:ntp"]["authentication-key"].remove(auth_key)
                config_leftover["tailf-ned-cisco-ios:ntp"]["trusted-key"].remove({"key-number": auth_key["number"]})

    if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("peer") or config_before.get("tailf-ned-cisco-ios:ntp",
                                                                                         {}).get("server"):
        openconfig_system_ntp.update({"openconfig-system:servers": {"openconfig-system:server": []}})
        openconfig_system_ntp_server_list = openconfig_system_ntp["openconfig-system:servers"][
            "openconfig-system:server"]
        # NTP SERVER
        if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("server", {}).get("peer-list"):
            xe_add_oc_ntp_server(config_before["tailf-ned-cisco-ios:ntp"]["server"]["peer-list"],
                             config_leftover["tailf-ned-cisco-ios:ntp"]["server"]["peer-list"],
                             openconfig_system_ntp_server_list, "SERVER", "", if_ip)
        # NTP PEER
        if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("peer", {}).get("peer-list"):
            xe_add_oc_ntp_server(config_before["tailf-ned-cisco-ios:ntp"]["peer"]["peer-list"],
                             config_leftover["tailf-ned-cisco-ios:ntp"]["peer"]["peer-list"],
                             openconfig_system_ntp_server_list, "PEER", "", if_ip)
        # VRF SERVER
        if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("server", {}).get("vrf"):
            for nso_vrf_index, vrf in enumerate(
                    config_before.get("tailf-ned-cisco-ios:ntp", {}).get("server", {}).get("vrf")):
                xe_add_oc_ntp_server(
                    config_before["tailf-ned-cisco-ios:ntp"]["server"]["vrf"][nso_vrf_index]["peer-list"],
                    config_leftover["tailf-ned-cisco-ios:ntp"]["server"]["vrf"][nso_vrf_index]["peer-list"],
                    openconfig_system_ntp_server_list, "SERVER", vrf["name"], if_ip)
        # VRF PEER
        if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("peer", {}).get("vrf"):
            for nso_vrf_index, vrf in enumerate(
                    config_before.get("tailf-ned-cisco-ios:ntp", {}).get("peer", {}).get("vrf")):
                xe_add_oc_ntp_server(
                    config_before["tailf-ned-cisco-ios:ntp"]["peer"]["vrf"][nso_vrf_index]["peer-list"],
                    config_leftover["tailf-ned-cisco-ios:ntp"]["peer"]["vrf"][nso_vrf_index]["peer-list"],
                    openconfig_system_ntp_server_list, "PEER", vrf["name"], if_ip)


def main(before: dict, leftover: dict, if_ip: dict) -> dict:
    """
    Translates NSO Device configurations to MDD OpenConfig configurations.

    Requires environment variables:
    NSO_HOST: str
    NSO_USERNAME: str
    NSO_PASSWORD: str
    NSO_DEVICE: str
    TEST - If True, sends generated OC configuration to NSO Server: str
    
    :param before: Original NSO Device configuration: dict
    :param leftover: NSO Device configuration minus configs replaced with MDD OC: dict
    :param if_ip: Map of interface names to IP addresses: dict
    :return: MDD Openconfig System configuration: dict
    """

    xe_system_config(before, leftover)
    xe_system_ssh_server(before, leftover)
    xe_system_ntp(before, leftover, if_ip)
    
    return openconfig_system


if __name__ == '__main__':
    import sys
    sys.path.append('../../')
    from package_nso_to_oc import common

    nso_host = os.environ.get("NSO_HOST")
    nso_username = os.environ.get("NSO_USERNAME", "ubuntu")
    nso_password = os.environ.get("NSO_PASSWORD", "admin")
    nso_device = os.environ.get("NSO_DEVICE", "xe1")
    test = os.environ.get("TEST", "False")

    config_before_dict = common.nso_get_device_config(nso_host, nso_username, nso_password, nso_device)
    config_leftover_dict = copy.deepcopy(config_before_dict)
    interface_ip_dict = common.xe_system_get_interface_ip_address(config_before_dict)
    main(config_before_dict, config_leftover_dict, interface_ip_dict)

    print(json.dumps(openconfig_system, indent=4))
    with open(f"../{nso_device}_configuration.json", "w") as b:
        b.write(json.dumps(config_before_dict, indent=4))
    with open(f"../{nso_device}_configuration_remaining.json", "w") as a:
        a.write(json.dumps(config_leftover_dict, indent=4))
    with open(f"../{nso_device}_openconfig_system.json", "w") as o:
        o.write(json.dumps(openconfig_system, indent=4))

    if test == 'True':
        common.test_nso_program_oc(nso_host, nso_username, nso_password, nso_device, openconfig_system)
