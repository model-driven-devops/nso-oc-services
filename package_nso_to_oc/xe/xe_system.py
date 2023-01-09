#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_configuration.json, save the NSO device
configuration minus parts replaced by OpenConfig to a file named {device_name}_configuration_remaining.json,
and save the MDD OpenConfig configuration to a file named {nso_device}_openconfig.json.

The script requires the following environment variables:
NSO_URL - URL for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation
TEST - True or False. True enables sending the OpenConfig to the NSO server after generation
"""

import sys
from pathlib import Path
from importlib.util import find_spec

system_notes = []

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
        "openconfig-system:ssh-server": {
            "openconfig-system:config": {},
            "openconfig-system-ext:algorithm": {
                "openconfig-system-ext:config": {}
            }
        },
        "openconfig-system-ext:services": {
            "openconfig-system-ext:http": {
                "openconfig-system-ext:config": {}
            },
            "openconfig-system-ext:config": {},
            "openconfig-system-ext:login-security-policy": {
                "openconfig-system-ext:config": {},
                "openconfig-system-ext:block-for": {"openconfig-system-ext:config": {}}
            },
            "openconfig-system-ext:boot-network": {
                "openconfig-system-ext:config": {},
            }
        }
    }
}

def xe_system_services(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System Services
    """
    openconfig_system_services = openconfig_system["openconfig-system:system"]["openconfig-system-ext:services"]
    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("domain", {}).get("lookup-conf", {}).get("lookup",
                                                                                                    True) is False:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-domain-lookup"] = False
        del config_leftover["tailf-ned-cisco-ios:ip"]["domain"]["lookup-conf"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-domain-lookup"] = True
    # login on-success log
    if type(config_before.get("tailf-ned-cisco-ios:login", {}).get("on-success", {}).get("log", '')) is list:
        openconfig_system_services["openconfig-system-ext:login-security-policy"]["openconfig-system-ext:config"][
            "openconfig-system-ext:on-success"] = True
        del config_leftover["tailf-ned-cisco-ios:login"]["on-success"]["log"]
    else:
        openconfig_system_services["openconfig-system-ext:login-security-policy"]["openconfig-system-ext:config"][
            "openconfig-system-ext:on-success"] = False
    # login on-failure log
    if type(config_before.get("tailf-ned-cisco-ios:login", {}).get("on-failure", {}).get("log", '')) is list:
        openconfig_system_services["openconfig-system-ext:login-security-policy"]["openconfig-system-ext:config"][
            "openconfig-system-ext:on-failure"] = True
        del config_leftover["tailf-ned-cisco-ios:login"]["on-failure"]["log"]
    else:
        openconfig_system_services["openconfig-system-ext:login-security-policy"]["openconfig-system-ext:config"][
            "openconfig-system-ext:on-failure"] = False
    # login block-for
    if config_before.get("tailf-ned-cisco-ios:login", {}).get("block-for", {}).get("seconds"):
        openconfig_system_services["openconfig-system-ext:login-security-policy"]["openconfig-system-ext:block-for"]["openconfig-system-ext:config"]["openconfig-system-ext:seconds"] = config_before.get("tailf-ned-cisco-ios:login", {}).get("block-for", {}).get("seconds")
        del config_leftover["tailf-ned-cisco-ios:login"]["block-for"]["seconds"]
    if config_before.get("tailf-ned-cisco-ios:login", {}).get("block-for", {}).get("attempts"):
        openconfig_system_services["openconfig-system-ext:login-security-policy"]["openconfig-system-ext:block-for"]["openconfig-system-ext:config"]["openconfig-system-ext:attempts"] = config_before.get("tailf-ned-cisco-ios:login", {}).get("block-for", {}).get("attempts")
        del config_leftover["tailf-ned-cisco-ios:login"]["block-for"]["attempts"]
    if config_before.get("tailf-ned-cisco-ios:login", {}).get("block-for", {}).get("within"):
        openconfig_system_services["openconfig-system-ext:login-security-policy"]["openconfig-system-ext:block-for"]["openconfig-system-ext:config"]["openconfig-system-ext:within"] = config_before.get("tailf-ned-cisco-ios:login", {}).get("block-for", {}).get("within")
        del config_leftover["tailf-ned-cisco-ios:login"]["block-for"]["within"]
    # Archive Logging
    if type(config_before.get("tailf-ned-cisco-ios:archive", {}).get("log", {}).get("config", {}).get("logging", {}).get("enable", '')) is list:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:archive-logging"] = True
        del config_leftover["tailf-ned-cisco-ios:archive"]["log"]["config"]["logging"]["enable"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:archive-logging"] = False
    # boot network
    if not config_before.get("tailf-ned-cisco-ios:boot", {}).get("network"):
        openconfig_system_services["openconfig-system-ext:boot-network"]["openconfig-system-ext:config"]["openconfig-system-ext:bootnetwork-enabled"] = "DISABLED"
    else:
        openconfig_system_services["openconfig-system-ext:boot-network"]["openconfig-system-ext:config"]["openconfig-system-ext:bootnetwork-enabled"] = "MANUAL_CONFIG"
    # IP bootp server
    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("bootp", {}).get("server", True) is False:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-bootp-server"] = False
        del config_leftover["tailf-ned-cisco-ios:ip"]["bootp"]["server"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-bootp-server"] = True
    # IP dns server
    if type(config_before.get("tailf-ned-cisco-ios:ip", {}).get("dns", {}).get("server", '')) is dict:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-dns-server"] = True
        del config_leftover["tailf-ned-cisco-ios:ip"]["dns"]["server"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-dns-server"] = False
    # IP identd
    if type(config_before.get("tailf-ned-cisco-ios:ip", {}).get("identd", '')) is list:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-identd"] = True
        del config_leftover["tailf-ned-cisco-ios:ip"]["identd"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-identd"] = False
    # IP http server
    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("http", {}).get("server", True) is False:
        openconfig_system_services["openconfig-system-ext:http"]["openconfig-system-ext:config"]["openconfig-system-ext:http-enabled"] = False
        del config_leftover["tailf-ned-cisco-ios:ip"]["http"]["server"]
    else:
        openconfig_system_services["openconfig-system-ext:http"]["openconfig-system-ext:config"]["openconfig-system-ext:http-enabled"] = True
    # IP RCMD rcp-enable
    if type(config_before.get("tailf-ned-cisco-ios:ip", {}).get("rcmd", {}).get("rcp-enable", '')) is list:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-rcmd-rcp-enable"] = True
        del config_leftover["tailf-ned-cisco-ios:ip"]["rcmd"]["rcp-enable"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-rcmd-rcp-enable"] = False
    # IP RCMD rsh-enable
    if type(config_before.get("tailf-ned-cisco-ios:ip", {}).get("rcmd", {}).get("rsh-enable", '')) is list:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-rcmd-rsh-enable"] = True
        del config_leftover["tailf-ned-cisco-ios:ip"]["rcmd"]["rsh-enable"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-rcmd-rsh-enable"] = False
    # IP finger
    if type(config_before.get("tailf-ned-cisco-ios:ip", {}).get("finger", '')) is dict:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:finger"] = True
        del config_leftover["tailf-ned-cisco-ios:ip"]["finger"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:finger"] = False
    # service config
    if type(config_before.get("tailf-ned-cisco-ios:service", {}).get("config", '')) is list:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-config"] = True
        del config_leftover["tailf-ned-cisco-ios:service"]["config"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-config"] = False
    # service tcp-small-servers
    if type(config_before.get("tailf-ned-cisco-ios:service", {}).get("tcp-small-servers", '')) is list:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-tcp-small-servers"] = True
        del config_leftover["tailf-ned-cisco-ios:service"]["tcp-small-servers"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-tcp-small-servers"] = False
    # service udp-small-servers
    if type(config_before.get("tailf-ned-cisco-ios:service", {}).get("udp-small-servers", '')) is list:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-udp-small-servers"] = True
        del config_leftover["tailf-ned-cisco-ios:service"]["udp-small-servers"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-udp-small-servers"] = False
    # service pad
    if config_before.get("tailf-ned-cisco-ios:service", {}).get("conf", {}).get("pad", True) is False:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-pad"] = False
        del config_leftover["tailf-ned-cisco-ios:service"]["conf"]["pad"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-pad"] = True
    # service password-encryption
    if type(config_before.get("tailf-ned-cisco-ios:service", {}).get("password-encryption", '')) is dict:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-password-encryption"] = True
        del config_leftover["tailf-ned-cisco-ios:service"]["password-encryption"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:service-password-encryption"] = False
def xe_system_config(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System Config
    """
    openconfig_system_config = openconfig_system["openconfig-system:system"]["openconfig-system:config"]

    openconfig_system_config["openconfig-system:hostname"] = config_before["tailf-ned-cisco-ios:hostname"]
    del config_leftover["tailf-ned-cisco-ios:hostname"]

    if config_before.get("tailf-ned-cisco-ios:banner", {}).get("login"):
        openconfig_system_config["openconfig-system:login-banner"] = config_before.get("tailf-ned-cisco-ios:banner",
                                                                                       {}).get("login")
        del config_leftover["tailf-ned-cisco-ios:banner"]["login"]

    if config_before.get("tailf-ned-cisco-ios:banner", {}).get("motd"):
        openconfig_system_config["openconfig-system:motd-banner"] = config_before.get("tailf-ned-cisco-ios:banner",
                                                                                      {}).get("motd")
        del config_leftover["tailf-ned-cisco-ios:banner"]["motd"]

    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("domain", {}).get("name"):
        openconfig_system_config["openconfig-system:domain-name"] = config_before.get("tailf-ned-cisco-ios:ip", {}).get(
            "domain", {}).get("name")
        del config_leftover["tailf-ned-cisco-ios:ip"]["domain"]["name"]

    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("options", {}).get("drop"):
        openconfig_system_config["openconfig-system-ext:ip-options"] = "DROP"
        del config_leftover["tailf-ned-cisco-ios:ip"]["options"]

    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("options", {}).get("ignore"):
        openconfig_system_config["openconfig-system-ext:ip-options"] = "IGNORE"
        del config_leftover["tailf-ned-cisco-ios:ip"]["options"]

    if (config_before.get("tailf-ned-cisco-ios:enable", {}).get("secret", {}).get("secret")) and \
            (config_before.get("tailf-ned-cisco-ios:enable", {}).get("secret", {}).get("type") == "0"):
        openconfig_system_config["openconfig-system-ext:enable-secret"] = config_before.get(
            "tailf-ned-cisco-ios:enable", {}).get("secret", {}).get("secret")
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
    openconfig_system_ssh_server_alg_config = openconfig_system["openconfig-system:system"]["openconfig-system:ssh-server"]["openconfig-system-ext:algorithm"]["openconfig-system-ext:config"]


    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("time-out"):
        openconfig_system_ssh_server_config["openconfig-system-ext:ssh-timeout"] = config_before.get(
            "tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("time-out")
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
        openconfig_system_ssh_server_config["openconfig-system-ext:absolute-timeout-minutes"] = \
        config_before["tailf-ned-cisco-ios:line"]["vty"][0]["absolute-timeout"]
        del config_leftover["tailf-ned-cisco-ios:line"]["vty"][0]["absolute-timeout"]

    if config_before["tailf-ned-cisco-ios:line"]["vty"][0].get("session-limit"):
        openconfig_system_ssh_server_config["openconfig-system:session-limit"] = config_before["tailf-ned-cisco-ios:line"]["vty"][0].get(
            "session-limit")
        del config_leftover["tailf-ned-cisco-ios:line"]["vty"][0]["session-limit"]

    if type(config_before.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("server", {}).get("algorithm", {}).get("encryption", '')) is list:
        openconfig_system_ssh_server_alg_config["openconfig-system-ext:encryption"] = config_before.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("server", {}).get("algorithm", {}).get("encryption")
        del config_leftover["tailf-ned-cisco-ios:ip"]["ssh"]["server"]["algorithm"]["encryption"]

    if type(config_before.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("server", {}).get("algorithm", {}).get("mac", '')) is list:
        openconfig_system_ssh_server_alg_config["openconfig-system-ext:mac"] = config_before.get("tailf-ned-cisco-ios:ip", {}).get("ssh", {}).get("server", {}).get("algorithm", {}).get("mac")
        del config_leftover["tailf-ned-cisco-ios:ip"]["ssh"]["server"]["algorithm"]["mac"]

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
            ntp_server_temp["openconfig-system:config"]["openconfig-system-ext:ntp-auth-key-id"] = ntp_server.get("key")
            del after_ntp_server_list[ntp_server_index]["key"]
        # source interface
        if ntp_server.get("source"):
            for k, v in ntp_server.get("source").items():
                nso_source_interface = f"{k}{v}"
                ntp_server_temp["openconfig-system:config"]["openconfig-system-ext:ntp-source-address"] = if_ip.get(
                    nso_source_interface)
                del after_ntp_server_list[ntp_server_index]["source"]
        # vrf
        if ntp_vrf:
            ntp_server_temp["openconfig-system:config"]["openconfig-system-ext:ntp-use-vrf"] = ntp_vrf

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
            openconfig_system_ntp["openconfig-system:config"][
                "openconfig-system:ntp-source-address"] = source_interface_ip
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
                try:  # trusted-keys can use a starting number, hyphen, and ending number in NED. Skip remove if this is the case.
                    config_leftover["tailf-ned-cisco-ios:ntp"]["trusted-key"].remove({"key-number": auth_key["number"]})
                except:
                    pass

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


def main(before: dict, leftover: dict, if_ip: dict, translation_notes: list = []) -> dict:
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
    :param if_ip: Map of interface names to IP addresses: dict
    :return: MDD Openconfig System configuration: dict
    """
    xe_system_config(before, leftover)
    xe_system_services(before, leftover)
    xe_system_ssh_server(before, leftover)
    xe_system_ntp(before, leftover, if_ip)
    translation_notes += system_notes

    return openconfig_system

if __name__ == "__main__":
    sys.path.append("../../")
    sys.path.append("../../../")

    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc import common
    else:
        import common_xe
        import common

    (config_before_dict, config_leftover_dict, interface_ip_dict) = common_xe.init_xe_configs()
    main(config_before_dict, config_leftover_dict, interface_ip_dict)
    config_name = "_system"
    config_remaining_name = "_remaining_system"
    oc_name = "_openconfig_system"
    common.print_and_test_configs("xe1", config_before_dict, config_leftover_dict, openconfig_system, 
        config_name, config_remaining_name, oc_name, system_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc import common
    else:
        from xe import common_xe
        import common
