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
import copy

TACACS = "tacacs"
RADIUS = "radius"
system_notes = []

openconfig_system = {
    "openconfig-system:system": {
        "openconfig-system:aaa": {
            "openconfig-system:server-groups": {
                "openconfig-system:server-group": []},
            "openconfig-system:accounting": {},
            "openconfig-system:authorization": {},
            "openconfig-system:authentication": {}
        },
        "openconfig-system:clock": {
            "openconfig-system:config": {},
        },
        "openconfig-system:config": {},
        "openconfig-system:dns": {
            "openconfig-system:servers": {
                "openconfig-system:server": []}
        },
        "openconfig-system:logging": {
            "openconfig-system:console": {},
            "openconfig-system-ext:terminal-monitor": {},
            "openconfig-system:remote-servers": {}
        },
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
                "openconfig-system-ext:config": {},
                "openconfig-system-ext:ip-http-timeout-policy": {"openconfig-system-ext:idle": {
                    "openconfig-system-ext:config": {}}}
            },
            "openconfig-system-ext:config": {},
            "openconfig-system-ext:login-security-policy": {
                "openconfig-system-ext:config": {},
                "openconfig-system-ext:block-for": {"openconfig-system-ext:config": {}}
            },
            "openconfig-system-ext:object-tracking": {
                "openconfig-system-ext:config": {"openconfig-system-ext:timer": {}},
                "openconfig-system-ext:object-track": []
            },
            "openconfig-system-ext:key-chains": {
                "openconfig-system-ext:key-chain": []
            },
            "openconfig-system-ext:boot-network": {
                "openconfig-system-ext:config": {},
            },
            "openconfig-system-ext:nat": {
                "openconfig-system-ext:pools": {"openconfig-system-ext:pool": []},
                "openconfig-system-ext:inside": {"openconfig-system-ext:source": {}
                }
            }
        },
        "openconfig-system-ext:timestamps": {
            "openconfig-system-ext:logging": {"openconfig-system-ext:config": {}},
            "openconfig-system-ext:debugging": {"openconfig-system-ext:config": {}}
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
    # track-object
    if config_before.get("tailf-ned-cisco-ios:track", {}).get("timer", {}).get("interface", {}).get("seconds"):
        openconfig_system_services["openconfig-system-ext:object-tracking"]["openconfig-system-ext:config"]["openconfig-system-ext:timer"]["openconfig-system-ext:interface-timer"] = config_before.get("tailf-ned-cisco-ios:track", {}).get("timer", {}).get("interface", {}).get("seconds")
        del config_leftover["tailf-ned-cisco-ios:track"]["timer"]
    if type(config_before.get("tailf-ned-cisco-ios:track", {}).get("track-object", '')) is list:
        xe_system_object_track(config_before, config_leftover)
    # key-chains
    if type(config_before.get("tailf-ned-cisco-ios:key", {}).get("chain", '')) is list or type(config_before.get("tailf-ned-cisco-ios:key", {}).get("tcp", {}).get("chain", '')) is list:
        xe_system_key_chain(config_before, config_leftover)
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
    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("bootp", {}).get("server", False) is True:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-bootp-server"] = True
        del config_leftover["tailf-ned-cisco-ios:ip"]["bootp"]["server"]
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-bootp-server"] = False
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
        del config_leftover["tailf-ned-cisco-ios:ip"]["http"]["server"]
    # IP http secure server
    openconfig_system_services["openconfig-system-ext:http"]["openconfig-system-ext:config"][
          "openconfig-system-ext:https-enabled"] = config_before.get("tailf-ned-cisco-ios:ip", {}).get(
            "http", {}).get("secure-server", False)
    del config_leftover["tailf-ned-cisco-ios:ip"]["http"]["secure-server"]
    # IP http max-connections
    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("http", {}).get("max-connections"):
        openconfig_system_services["openconfig-system-ext:http"]["openconfig-system-ext:config"][
            "openconfig-system-ext:ip-http-max-connections"] = config_before.get("tailf-ned-cisco-ios:ip", {}).get(
                "http", {}).get("max-connections")
        del config_leftover["tailf-ned-cisco-ios:ip"]["http"]["max-connections"]
    # IP http ciphersuite
    if len(config_before.get("tailf-ned-cisco-ios:ip", {}).get("http", {}).get("secure-ciphersuite", [])) > 0:
        openconfig_system_services["openconfig-system-ext:http"]["openconfig-system-ext:config"][
            "openconfig-system-ext:ip-http-secure-ciphersuite"] = config_before.get("tailf-ned-cisco-ios:ip", {}).get(
                "http", {}).get("secure-ciphersuite")
        del config_leftover["tailf-ned-cisco-ios:ip"]["http"]["secure-ciphersuite"]
    # IP http timeout-policy - idle
    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("http", {}).get("timeout-policy", {}).get(
        "idle"):
        openconfig_system_services["openconfig-system-ext:http"]["openconfig-system-ext:ip-http-timeout-policy"]["openconfig-system-ext:idle"]["openconfig-system-ext:config"]["openconfig-system-ext:connection"] = config_before.get("tailf-ned-cisco-ios:ip", {}).get("http", {}).get("timeout-policy", {}).get("idle")
        del config_leftover["tailf-ned-cisco-ios:ip"]["http"]["timeout-policy"]["idle"]
    # IP http timeout-policy - life
    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("http", {}).get("timeout-policy", {}).get(
        "life"):
        openconfig_system_services["openconfig-system-ext:http"]["openconfig-system-ext:ip-http-timeout-policy"][
            "openconfig-system-ext:idle"]["openconfig-system-ext:config"]["openconfig-system-ext:life"] = config_before.get(
                "tailf-ned-cisco-ios:ip", {}).get("http", {}).get("timeout-policy", {}).get("life")
        del config_leftover["tailf-ned-cisco-ios:ip"]["http"]["timeout-policy"]["life"]
    # IP http timeout-policy - requests
    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("http", {}).get("timeout-policy", {}).get(
        "requests"):
        openconfig_system_services["openconfig-system-ext:http"]["openconfig-system-ext:ip-http-timeout-policy"][
            "openconfig-system-ext:idle"]["openconfig-system-ext:config"]["openconfig-system-ext:requests"] = config_before.get(
                "tailf-ned-cisco-ios:ip", {}).get("http", {}).get("timeout-policy", {}).get("requests")
        del config_leftover["tailf-ned-cisco-ios:ip"]["http"]["timeout-policy"]["requests"]
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
    # gratuitous-arp
    if config_before.get("tailf-ned-cisco-ios:ip", {}).get("gratuitous-arps-conf", {}).get("gratuitous-arps", True) is False:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-gratuitous-arps"] = False
    else:
        openconfig_system_services["openconfig-system-ext:config"]["openconfig-system-ext:ip-gratuitous-arps"] = True
        if config_leftover.get("tailf-ned-cisco-ios:ip", {}).get("gratuitous-arps-conf", {}).get("gratuitous-arps"):
            del config_leftover["tailf-ned-cisco-ios:ip"]["gratuitous-arps-conf"]["gratuitous-arps"]
    # aaa server-groups

    # gather group and server configurations

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

def xe_system_object_track(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System Object Tracking
    """
    track_object = {
        "openconfig-system-ext:id": "",
        "openconfig-system-ext:type": "",
        "openconfig-system-ext:config": {
            "openconfig-system-ext:id": "",
            "openconfig-system-ext:track-interface": "",
            "openconfig-system-ext:track-parameter": ""
        }
    }
    for track_object_index, track_object_list in enumerate(config_before.get("tailf-ned-cisco-ios:track", {}).get("track-object", '')):
        tmp_track_object = copy.deepcopy(track_object)
        for k, v in track_object_list.items():
            if "object-number" in k:
                track_id = str(v)
                tmp_track_object["openconfig-system-ext:id"] = str(v)
                tmp_track_object["openconfig-system-ext:config"]["openconfig-system-ext:id"] = str(v)
            elif "interface" in k:
                tmp_track_object["openconfig-system-ext:type"] = 'INTERFACE'
                for key in v:
                    # Check if key is of type string.  This is the interface type and number
                    if isinstance(key, str) and isinstance(v[key], str):  # GigabitEthernet number is str
                        tmp_track_object["openconfig-system-ext:config"]["openconfig-system-ext:track-interface"] = key + v[key]
                    elif isinstance(key, str) and isinstance(v[key], int):  # VLAN number is int
                        tmp_track_object["openconfig-system-ext:config"]["openconfig-system-ext:track-interface"] = key + str(v[key])
                    if type(v.get("ip", {}).get("routing", '')) is list:
                        tmp_track_object["openconfig-system-ext:config"]["openconfig-system-ext:track-parameter"] = 'IP-ROUTING'
                    elif type(v.get("line-protocol", '')) is list:
                        tmp_track_object["openconfig-system-ext:config"]["openconfig-system-ext:track-parameter"] = 'LINE-PROTOCOL'
                    else:
                        track_parameter = 'UNKNOWN'
            else:
                print("Invalid track_object data structure")
        openconfig_system["openconfig-system:system"]["openconfig-system-ext:services"]["openconfig-system-ext:object-tracking"]["openconfig-system-ext:object-track"].append(tmp_track_object)
    if config_leftover["tailf-ned-cisco-ios:track"]["track-object"]:
        del config_leftover["tailf-ned-cisco-ios:track"]["track-object"]


def xe_system_key_chain(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System Key Chain
    """
    key_chain = {
        "openconfig-system-ext:name": "",
        "openconfig-system-ext:type": "",
        "openconfig-system-ext:keys": []
    }
    key = {
        "openconfig-system-ext:id": None,
        "openconfig-system-ext:config": {
            "openconfig-system-ext:id": None,
            "openconfig-system-ext:key-string": "",
            "openconfig-system-ext:cryptographic-algorithm": "",
            "openconfig-system-ext:accept-lifetime": {},
            "openconfig-system-ext:send-lifetime": {},
        }
    }
    key_tcp = {
        "openconfig-system-ext:id": None,
        "openconfig-system-ext:config": {
            "openconfig-system-ext:id": None,
            "openconfig-system-ext:key-string": "",
            "openconfig-system-ext:cryptographic-algorithm-tcp": "",
            "openconfig-system-ext:send-id": None,
            "openconfig-system-ext:recv-id": None,
            "openconfig-system-ext:accept-lifetime": {},
            "openconfig-system-ext:send-lifetime": {},
        }
    }
    # NA key chain
    for key_chain_index, key_chain_list in enumerate(config_before.get("tailf-ned-cisco-ios:key", {}).get("chain", '')):
        tmp_key_chain = copy.deepcopy(key_chain)
        tmp_key_chain["openconfig-system-ext:type"] = "NOT_APPLICABLE"
        for k, v in key_chain_list.items():
            if "name" in k:
                tmp_key_chain["openconfig-system-ext:name"] = v
            elif "key" in k:
                for keydata in v:
                    tmp_key = copy.deepcopy(key)
                    accept_lifetime_global = True
                    send_lifetime_global = True
                    for keydata_k, keydata_v in keydata.items():
                        if keydata_k == "id":
                            tmp_key["openconfig-system-ext:id"] = keydata_v
                            tmp_key["openconfig-system-ext:config"]["openconfig-system-ext:id"] = keydata_v
                        elif keydata_k == "cryptographic-algorithm":
                            tmp_key["openconfig-system-ext:config"]["openconfig-system-ext:cryptographic-algorithm"] = str(keydata_v)
                        elif keydata_k == "key-string":
                            for ks_k, ks_v in keydata_v.items():
                                if "type" in ks_k:
                                    keystring_type = ks_v
                                elif "secret" in ks_k:
                                    tmp_key["openconfig-system-ext:config"]["openconfig-system-ext:key-string"] = str(ks_v)
                        elif keydata_k == "accept-lifetime":
                            for al_k, al_v in keydata_v.items():
                                if "local" in al_k:
                                    accept_lifetime_global = False
                                    tmp_lt = xe_parse_keychain_lifetime(al_v)
                                    tmp_key["openconfig-system-ext:config"]["openconfig-system-ext:accept-lifetime"].update({"openconfig-system-ext:local": {}})
                                    tmp_key["openconfig-system-ext:config"]["openconfig-system-ext:accept-lifetime"]["openconfig-system-ext:local"] = tmp_lt
                            if accept_lifetime_global == True:
                                tmp_lt = xe_parse_keychain_lifetime(keydata_v)
                                tmp_key["openconfig-system-ext:config"]["openconfig-system-ext:accept-lifetime"] = tmp_lt
                        elif keydata_k == "send-lifetime":
                            for sl_k, sl_v in keydata_v.items():
                                if "local" in sl_k:
                                    send_lifetime_global = False
                                    tmp_lt = xe_parse_keychain_lifetime(sl_v)
                                    tmp_key["openconfig-system-ext:config"]["openconfig-system-ext:send-lifetime"].update({"openconfig-system-ext:local": {}})
                                    tmp_key["openconfig-system-ext:config"]["openconfig-system-ext:send-lifetime"]["openconfig-system-ext:local"] = tmp_lt
                            if send_lifetime_global == True:
                                tmp_lt = xe_parse_keychain_lifetime(keydata_v)
                                tmp_key["openconfig-system-ext:config"]["openconfig-system-ext:send-lifetime"] = tmp_lt
                    tmp_key_chain["openconfig-system-ext:keys"].append(tmp_key)

        openconfig_system["openconfig-system:system"]["openconfig-system-ext:services"]["openconfig-system-ext:key-chains"]["openconfig-system-ext:key-chain"].append(tmp_key_chain)
    if config_leftover.get("tailf-ned-cisco-ios:key", {}).get("chain"):
        del config_leftover["tailf-ned-cisco-ios:key"]["chain"]

    # TCP key chain
    for key_chain_index, key_chain_list in enumerate(config_before.get("tailf-ned-cisco-ios:key", {}).get("tcp", {}).get("chain", '')):
        tmp_key_chain = copy.deepcopy(key_chain)
        tmp_key_chain["openconfig-system-ext:type"] = "TCP"
        for k, v in key_chain_list.items():
            if "name" in k:
                tmp_key_chain["openconfig-system-ext:name"] = v
            elif "key" in k:
                for keydata in v:
                    tmp_key_tcp = copy.deepcopy(key_tcp)
                    accept_lifetime_global = True
                    send_lifetime_global = True
                    for keydata_k, keydata_v in keydata.items():
                        if keydata_k == "id":
                            tmp_key_tcp["openconfig-system-ext:id"] = keydata_v
                            tmp_key_tcp["openconfig-system-ext:config"]["openconfig-system-ext:id"] = keydata_v
                        elif keydata_k == "send-id":
                            tmp_key_tcp["openconfig-system-ext:config"]["openconfig-system-ext:send-id"] = keydata_v
                        elif keydata_k == "recv-id":
                            tmp_key_tcp["openconfig-system-ext:config"]["openconfig-system-ext:recv-id"] = keydata_v
                        elif "cryptographic-algorithm" in keydata_k:
                            tmp_key_tcp["openconfig-system-ext:config"]["openconfig-system-ext:cryptographic-algorithm-tcp"] = str(keydata_v)
                        elif keydata_k == "key-string":
                            for ks_k, ks_v in keydata_v.items():
                                if "type" in ks_k:
                                    keystring_type = ks_v
                                elif "secret" in ks_k:
                                    tmp_key_tcp["openconfig-system-ext:config"]["openconfig-system-ext:key-string"] = str(ks_v)
                        elif keydata_k == "accept-lifetime":
                            for al_k, al_v in keydata_v.items():
                                if "local" in al_k:
                                    accept_lifetime_global = False
                                    tmp_lt = xe_parse_keychain_lifetime(al_v)
                                    tmp_key_tcp["openconfig-system-ext:config"]["openconfig-system-ext:accept-lifetime"].update({"openconfig-system-ext:local": {}})
                                    tmp_key_tcp["openconfig-system-ext:config"]["openconfig-system-ext:accept-lifetime"]["openconfig-system-ext:local"] = tmp_lt
                            if accept_lifetime_global == True:
                                tmp_lt = xe_parse_keychain_lifetime(keydata_v)
                                tmp_key_tcp["openconfig-system-ext:config"]["openconfig-system-ext:accept-lifetime"] = tmp_lt
                        elif keydata_k == "send-lifetime":
                            for sl_k, sl_v in keydata_v.items():
                                if "local" in sl_k:
                                    send_lifetime_global = False
                                    tmp_lt = xe_parse_keychain_lifetime(sl_v)
                                    tmp_key_tcp["openconfig-system-ext:config"]["openconfig-system-ext:send-lifetime"].update({"openconfig-system-ext:local": {}})
                                    tmp_key_tcp["openconfig-system-ext:config"]["openconfig-system-ext:send-lifetime"]["openconfig-system-ext:local"] = tmp_lt
                            if send_lifetime_global == True:
                                tmp_lt = xe_parse_keychain_lifetime(keydata_v)
                                tmp_key_tcp["openconfig-system-ext:config"]["openconfig-system-ext:send-lifetime"] = tmp_lt
                    tmp_key_chain["openconfig-system-ext:keys"].append(tmp_key_tcp)

        openconfig_system["openconfig-system:system"]["openconfig-system-ext:services"]["openconfig-system-ext:key-chains"]["openconfig-system-ext:key-chain"].append(tmp_key_chain)
    if config_leftover.get("tailf-ned-cisco-ios:key", {}).get("tcp"):
        del config_leftover["tailf-ned-cisco-ios:key"]["tcp"]

def xe_parse_keychain_lifetime(lifetime_dict: dict):
    """
    Parse the keychain lifetime dataset.
    Returns: lifetime dict
    """
    lifetime = {
        "openconfig-system-ext:start-time": "",
        "openconfig-system-ext:start-date": None,
        "openconfig-system-ext:start-month": "",
        "openconfig-system-ext:start-year": None
    }

    tmp_lifetime = copy.deepcopy(lifetime)
    for k, v in lifetime_dict.items():
        if "start-time" in k:
            tmp_lifetime["openconfig-system-ext:start-time"] = str(v)
        elif "start-date" in k:
            tmp_lifetime["openconfig-system-ext:start-date"] = v
        elif "start-month" in k:
            tmp_lifetime["openconfig-system-ext:start-month"] = str(v)
        elif "start-year" in k:
            tmp_lifetime["openconfig-system-ext:start-year"] = v
        elif "infinite" in k:
            tmp_lifetime["openconfig-system-ext:infinite"] = True
        elif "duration" in k:
            tmp_lifetime["openconfig-system-ext:duration"] = v
        elif "stop-time" in k:
            tmp_lifetime["openconfig-system-ext:stop-time"] = str(v)
        elif "stop-date" in k:
            tmp_lifetime["openconfig-system-ext:stop-date"] = str(v)
        elif "stop-month" in k:
            tmp_lifetime["openconfig-system-ext:stop-month"] = str(v)
        elif "stop-year" in k:
            tmp_lifetime["openconfig-system-ext:stop-year"] = str(v)
    return(tmp_lifetime)


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
            if ntp_server.get("source", {}).get("Port-channel-subinterface"):
                for k, v in ntp_server.get("source").get("Port-channel-subinterface").items():
                    nso_source_interface = f"{k}{v}"
                    ntp_server_temp["openconfig-system:config"]["openconfig-system-ext:ntp-source-address"] = if_ip.get(
                        nso_source_interface)
                    del after_ntp_server_list[ntp_server_index]["source"]
            else:
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

    # Enable NTP
    if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("server", {}).get("peer-list") or \
        config_before.get("tailf-ned-cisco-ios:ntp", {}).get("server", {}).get("vrf") or \
        config_before.get("tailf-ned-cisco-ios:ntp", {}).get("peer", {}).get("peer-list") or \
        config_before.get("tailf-ned-cisco-ios:ntp", {}).get("peer", {}).get("vrf"):
        openconfig_system_ntp["openconfig-system:config"]["openconfig-system:enabled"] = True

    if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("authenticate"):
        openconfig_system_ntp["openconfig-system:config"]["openconfig-system:enable-ntp-auth"] = True
        del config_leftover["tailf-ned-cisco-ios:ntp"]["authenticate"]

    if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("logging"):
        openconfig_system_ntp["openconfig-system:config"]["openconfig-system-ext:ntp-enable-logging"] = True
        del config_leftover["tailf-ned-cisco-ios:ntp"]["logging"]

    if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("source"):
        if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("source", {}).get("Port-channel-subinterface"):
            for i, n in config_before.get("tailf-ned-cisco-ios:ntp", {}).get("source").get(
                    "Port-channel-subinterface").items():
                source_interface = f"{i}{n}"
                source_interface_ip = if_ip.get(source_interface)
                openconfig_system_ntp["openconfig-system:config"][
                    "openconfig-system:ntp-source-address"] = source_interface_ip
                del config_leftover["tailf-ned-cisco-ios:ntp"]["source"]
        else:
            for i, n in config_before.get("tailf-ned-cisco-ios:ntp", {}).get("source").items():
                source_interface = f"{i}{n}"
                source_interface_ip = if_ip.get(source_interface)
                openconfig_system_ntp["openconfig-system:config"][
                    "openconfig-system:ntp-source-address"] = source_interface_ip
            del config_leftover["tailf-ned-cisco-ios:ntp"]["source"]

    if config_before.get("tailf-ned-cisco-ios:ntp", {}).get("trusted-key") and config_before.get(
            "tailf-ned-cisco-ios:ntp", {}).get("authentication-key"):
        trusted_key_numbers = []
        for index, key_info in enumerate(config_before.get("tailf-ned-cisco-ios:ntp", {}).get("trusted-key")):
            if key_info.get("end-key-number"):
                # Get trusted keys from range (key-number, end-key-number)
                temp_key_list = list(range(config_before.get("tailf-ned-cisco-ios:ntp", {}).get("trusted-key", [])[index].get(
                    "key-number"), config_before.get("tailf-ned-cisco-ios:ntp", {}).get("trusted-key", [])[index].get(
                        "end-key-number") + 1))
                trusted_key_numbers.extend(temp_key_list)
            else:
                temp_key_numbers = config_before.get("tailf-ned-cisco-ios:ntp", {}).get("trusted-key", [])[index].get(
                    "key-number")
                trusted_key_numbers.append(temp_key_numbers)

        auth_key_list = []
        for auth_key in config_before.get("tailf-ned-cisco-ios:ntp", {}).get("authentication-key"):
            if auth_key["number"] in trusted_key_numbers and auth_key.get("md5"):
                key_dict = {"openconfig-system:key-id": auth_key["number"],
                            "openconfig-system:config": {"openconfig-system:key-id": auth_key["number"],
                                                         "openconfig-system:key-type": "NTP_AUTH_MD5",
                                                         "openconfig-system:key-value": auth_key.get("md5").get(
                                                             "secret")}
                            }
                openconfig_system_ntp["openconfig-system:ntp-keys"]["openconfig-system:ntp-key"].append(key_dict)
                auth_key_list.append(auth_key["number"])
                config_leftover["tailf-ned-cisco-ios:ntp"]["authentication-key"].remove(auth_key)
                try:  # trusted-keys can use a starting number, hyphen, and ending number in NED. Skip remove if this is the case.
                    config_leftover["tailf-ned-cisco-ios:ntp"]["trusted-key"].remove({"key-number": auth_key["number"]})
                except:
                    pass

        # Remove trusted keys from range (key-number, end-key-number)
        leftover_trusted_key = []
        for trusted_key in config_before.get("tailf-ned-cisco-ios:ntp", {}).get("trusted-key"):
            if "end-key-number" in trusted_key:
                config_leftover["tailf-ned-cisco-ios:ntp"]["trusted-key"].remove({"key-number": trusted_key["key-number"],
                    "hyphen": [None], "end-key-number": trusted_key["end-key-number"]})
                leftover_trusted_key.extend(list(set(list(range(trusted_key["key-number"], trusted_key[
                    "end-key-number"] + 1))) - set(auth_key_list)))
        # Re-add to config_leftover all trusted keys not configured
        if leftover_trusted_key:
            for reconf_trusted_key in leftover_trusted_key:
                config_leftover["tailf-ned-cisco-ios:ntp"]["trusted-key"].append({"key-number": reconf_trusted_key})

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

def xe_system_aaa(config_before: dict, config_leftover: dict, if_ip: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System AAA
    """
    oc_system_server_group = openconfig_system["openconfig-system:system"]["openconfig-system:aaa"]["openconfig-system:server-groups"]["openconfig-system:server-group"]
    oc_system_aaa_accounting = openconfig_system["openconfig-system:system"]["openconfig-system:aaa"]["openconfig-system:accounting"]
    oc_system_aaa_authorization = openconfig_system["openconfig-system:system"]["openconfig-system:aaa"]["openconfig-system:authorization"]
    oc_system_aaa_authentication = openconfig_system["openconfig-system:system"]["openconfig-system:aaa"]["openconfig-system:authentication"]
    tacacs_group_list = config_before.get("tailf-ned-cisco-ios:aaa", {}).get("group", {}).get("server", {}).get("tacacs-plus")
    radius_group_list = config_before.get("tailf-ned-cisco-ios:aaa", {}).get("group", {}).get("server", {}).get("radius")
    tacacs_server_list = config_before.get("tailf-ned-cisco-ios:tacacs", {}).get("server")
    radius_server_list = config_before.get("tailf-ned-cisco-ios:radius", {}).get("server")
    accounting_dict = config_before.get("tailf-ned-cisco-ios:aaa", {}).get("accounting")
    authorization_dict = config_before.get("tailf-ned-cisco-ios:aaa", {}).get("authorization")
    authentication_dict = config_before.get("tailf-ned-cisco-ios:aaa", {}).get("authentication")
    authentication_user_list = config_before.get("tailf-ned-cisco-ios:username")

    # TACACS GROUP
    if tacacs_group_list:
        for tacacs_group_index, tacacs_group in enumerate(tacacs_group_list):
            process_aaa_tacacs(oc_system_server_group, config_leftover, if_ip, tacacs_group_index, tacacs_group, tacacs_server_list)

    # RADIUS GROUP
    if radius_group_list:
        for radius_group_index, radius_group in enumerate(radius_group_list):
            process_aaa_radius(oc_system_server_group, config_leftover, if_ip, radius_group_index, radius_group, radius_server_list)

    # AAA ACCOUNTING
    if accounting_dict:
        if accounting_dict.get("commands") or accounting_dict.get("exec"):
            temp_aaa_accounting = {
                "openconfig-system:config": set_accounting_method(oc_system_aaa_accounting, config_leftover, accounting_dict),
                "openconfig-system:events": set_accounting_event(oc_system_aaa_accounting, config_leftover, accounting_dict)
            }
            oc_system_aaa_accounting.update(temp_aaa_accounting)

    # AAA AUTHORIZATION
    if authorization_dict:
        if authorization_dict.get("commands") or authorization_dict.get("exec"):
            temp_aaa_authorization = {
                "openconfig-system:config": set_authorization_method(oc_system_aaa_authorization, config_leftover, authorization_dict),
                "openconfig-system:events": set_authorization_event(oc_system_aaa_authorization, config_leftover, authorization_dict)
            }
            oc_system_aaa_authorization.update(temp_aaa_authorization)

    # AAA AUTHENTICATION
    if authentication_dict or authentication_user_list:
        temp_aaa_authentication = {
            "openconfig-system:config": set_authentication_method(oc_system_aaa_authentication, config_leftover, authentication_dict),
            "openconfig-system:admin-user": set_authentication_admin(oc_system_aaa_authentication, config_leftover, authentication_user_list),
            "openconfig-system:users": set_authentication_user(oc_system_aaa_authentication, config_leftover, authentication_user_list)
        }
        oc_system_aaa_authentication.update(temp_aaa_authentication)

        updated_usernames = []

        for username in config_leftover.get("tailf-ned-cisco-ios:username", []):
            if username:
                updated_usernames.append(username)

        if len(updated_usernames) > 0:
            config_leftover["tailf-ned-cisco-ios:username"] = updated_usernames
        elif "tailf-ned-cisco-ios:username" in config_leftover:
            del config_leftover["tailf-ned-cisco-ios:username"]

    cleanup_server_access(config_leftover, f"{TACACS}-plus", TACACS)
    cleanup_server_access(config_leftover, RADIUS, RADIUS)

def process_aaa_tacacs(oc_system_server_group, config_leftover, if_ip, tacacs_group_index, tacacs_group, tacacs_server_list):
    tacacs_group_leftover = config_leftover.get("tailf-ned-cisco-ios:aaa", {}).get("group", {}).get("server", {}).get("tacacs-plus")[tacacs_group_index]
    # If we got here, we init an empty dict and append to oc_system_server_group list for future use.
    oc_system_server_group.append({})
    tac_group_index = len(oc_system_server_group) - 1
    set_tacacs_group_config(tacacs_group_leftover, config_leftover, oc_system_server_group, if_ip, tac_group_index, tacacs_group, tacacs_server_list)

def process_aaa_radius(oc_system_server_group, config_leftover, if_ip, radius_group_index, radius_group, radius_server_list):
    radius_group_leftover = config_leftover.get("tailf-ned-cisco-ios:aaa", {}).get("group", {}).get("server", {}).get("radius")[radius_group_index]
    # If we got here, we init an empty dict and append to oc_system_server_group list for future use.
    oc_system_server_group.append({})
    rad_group_index = len(oc_system_server_group) - 1
    set_radius_group_config(radius_group_leftover, config_leftover, oc_system_server_group, if_ip, rad_group_index, radius_group, radius_server_list)

def set_tacacs_group_config(tacacs_group_leftover, config_leftover, oc_system_server_group, if_ip, tac_group_index, tacacs_group, tacacs_server_list):
    # TACACS SERVER-GROUPS
    oc_system_server_group[tac_group_index]["openconfig-system:name"] = f'{tacacs_group.get("name")}'
    temp_tacacs_group = {"openconfig-system:config": {
        "openconfig-system:type": "TACACS",
        "openconfig-system:name": f'{tacacs_group.get("name")}'},
        "openconfig-system:servers": set_server_tacacs_config(tacacs_group_leftover, config_leftover, oc_system_server_group, if_ip, tac_group_index, tacacs_group, tacacs_server_list)
    }
    oc_system_server_group[tac_group_index].update(temp_tacacs_group)

def set_radius_group_config(radius_group_leftover, config_leftover, oc_system_server_group, if_ip, rad_group_index, radius_group, radius_server_list):
    # RADIUS SERVER-GROUPS
    oc_system_server_group[rad_group_index]["openconfig-system:name"] = f'{radius_group.get("name")}'
    # RADIUS SERVER-GROUP NAME AND TYPE
    temp_radius_group = {"openconfig-system:config": {
        "openconfig-system:type": "RADIUS",
        "openconfig-system:name": f'{radius_group.get("name")}'},
        "openconfig-system:servers": set_server_radius_config(radius_group_leftover, config_leftover, oc_system_server_group, if_ip, rad_group_index, radius_group, radius_server_list)
    }
    oc_system_server_group[rad_group_index].update(temp_radius_group)

def set_server_tacacs_config(tacacs_group_leftover, config_leftover, oc_system_server_group, if_ip, tac_group_index, tacacs_group, tacacs_server_list):
    tac_server = {"openconfig-system:server": []}
    tac_server_list = tac_server["openconfig-system:server"]
    source_interface_ip = None
    # TACACS SOURCE-INTERFACE
    for i, n in tacacs_group.get("ip", {}).get("tacacs", {}).get("source-interface", {}).items():
        source_interface = f"{i}{n}"
        source_interface_ip = if_ip.get(source_interface)
        if source_interface_ip:
            del config_leftover["tailf-ned-cisco-ios:aaa"]["group"]["server"]["tacacs-plus"][tac_group_index]["ip"]["tacacs"][
                "source-interface"]

    if tacacs_server_list:
        for server_list_index, server in enumerate(tacacs_server_list):
            for i in range(len(tacacs_group.get("server", {}).get("name", []))):
                if server.get("name") in tacacs_group["server"]["name"][i]["name"]:
                    # TACACS SERVER NAME, ADDRESS AND TIMEOUT
                    temp_tacacs_server = {"openconfig-system:address": f'{server.get("address", {}).get("ipv4")}',
                                          "openconfig-system:config": {
                                              "openconfig-system:address": f'{server.get("address", {}).get("ipv4")}',
                                              "openconfig-system:name": f'{server.get("name")}',
                                              "openconfig-system:timeout": f'{server.get("timeout", 5)}'},
                                          "openconfig-system:tacacs": {"openconfig-system:config": {
                                              "openconfig-system:port": f'{server.get("port", 49)}',
                                              "openconfig-system:secret-key": f'{server.get("key", {}).get("secret")}'
                                          }}}
                    if source_interface_ip:
                        temp_tacacs_server["openconfig-system:tacacs"]["openconfig-system:config"]["openconfig-system:source-address"] = source_interface_ip
                    tac_server_list.append(temp_tacacs_server)
                    config_leftover["tailf-ned-cisco-ios:aaa"]["group"]["server"]["tacacs-plus"][tac_group_index][
                        "server"]["name"][i] = None
            config_leftover["tailf-ned-cisco-ios:tacacs"]["server"][server_list_index] = None

    return tac_server

def set_server_radius_config(radius_group_leftover, config_leftover, oc_system_server_group, if_ip, rad_group_index,
                             radius_group, radius_server_list):
    rad_server = {"openconfig-system:server": []}
    rad_server_list = rad_server["openconfig-system:server"]
    source_interface_ip = None
    # RADIUS SOURCE-INTERFACE
    for i, n in radius_group.get("ip", {}).get("radius", {}).get("source-interface", {}).items():
        source_interface = f"{i}{n}"
        source_interface_ip = if_ip.get(source_interface)
        if source_interface_ip:
            del \
            config_leftover["tailf-ned-cisco-ios:aaa"]["group"]["server"]["radius"][rad_group_index]["ip"]["radius"][
                "source-interface"]

    if radius_server_list:
        for server_list_index, server in enumerate(radius_server_list):
            for i in range(len(radius_group.get("server", {}).get("name", []))):
                if server.get("id") in radius_group["server"]["name"][i]["name"]:
                    # RADIUS SERVER NAME, ADDRESS AND TIMEOUT
                    temp_radius_server = {
                        "openconfig-system:address": f'{server.get("address", {}).get("ipv4", {}).get("host")}',
                        "openconfig-system:config": {
                            "openconfig-system:address": f'{server.get("address", {}).get("ipv4", {}).get("host")}',
                            "openconfig-system:name": f'{server.get("id")}',
                            "openconfig-system:timeout": f'{server.get("timeout", 5)}'},
                        "openconfig-system:radius": {"openconfig-system:config": {
                            "openconfig-system:acct-port": f'{server.get("address", {}).get("ipv4", {}).get("acct-port")}',
                            "openconfig-system:auth-port": f'{server.get("address", {}).get("ipv4", {}).get("auth-port")}'
                        }}}
                    if source_interface_ip:
                        temp_radius_server["openconfig-system:radius"]["openconfig-system:config"][
                            "openconfig-system:source-address"] = source_interface_ip
                    if server.get("key", {}).get("secret"):
                        temp_radius_server["openconfig-system:radius"]["openconfig-system:config"][
                            "openconfig-system:secret-key"] = server.get("key", {}).get("secret")
                    rad_server_list.append(temp_radius_server)
                    config_leftover["tailf-ned-cisco-ios:aaa"]["group"]["server"]["radius"][rad_group_index][
                        "server"]["name"][i] = None
            config_leftover["tailf-ned-cisco-ios:radius"]["server"][server_list_index] = None

    return rad_server

def set_accounting_method(oc_system_aaa_accounting, config_leftover, accounting_dict):
    # AAA ACCOUNTING GROUPS
    acc_method = {"openconfig-system:accounting-method": []}
    acc_method_list = acc_method["openconfig-system:accounting-method"]
    group = group2 = group3 = None

    if accounting_dict.get("commands"):
        for i, command in enumerate(accounting_dict.get("commands")):
            if command.get("group"):
                if command.get("group") == 'tacacs+':
                    group = 'TACACS_ALL'
                else:
                    group = command.get("group")
                acc_method_list.append(group)
            if command.get("group2") and command.get("group2", {}).get("group"):
                if command.get("group2", {}).get("group") == 'tacacs+':
                    group2 = 'TACACS_ALL'
                elif command.get("group2", {}).get("group"):
                    group2 = command.get("group2", {}).get("group")
                acc_method_list.append(group2)
            if command.get("group3") and command.get("group3", {}).get("group"):
                if command.get("group2", {}).get("group") and command.get("group3", {}).get("group") == 'tacacs+':
                    group3 = 'TACACS_ALL'
                elif command.get("group2", {}).get("group") and command.get("group3", {}).get("group"):
                    group3 = command.get("group3", {}).get("group")
                acc_method_list.append(group3)
        del config_leftover["tailf-ned-cisco-ios:aaa"]["accounting"]["commands"]
    if accounting_dict.get("exec"):
        for i, exe in enumerate(accounting_dict.get("exec")):
            if exe.get("group"):
                if exe.get("group") == 'tacacs+':
                    group = 'TACACS_ALL'
                else:
                    group = exe.get("group")
                acc_method_list.append(group)
            if exe.get("group2") and exe.get("group2", {}).get("group"):
                if exe.get("group2", {}).get("group") == 'tacacs+':
                    group2 = 'TACACS_ALL'
                elif exe.get("group2", {}).get("group"):
                    group2 = exe.get("group2", {}).get("group")
                acc_method_list.append(group2)
            if exe.get("group3") and exe.get("group3", {}).get("group"):
                if exe.get("group2", {}).get("group") and exe.get("group3", {}).get("group") == 'tacacs+':
                    group3 = 'TACACS_ALL'
                elif exe.get("group2", {}).get("group") and exe.get("group3", {}).get("group"):
                    group3 = exe.get("group3", {}).get("group")
                acc_method_list.append(group3)
        del config_leftover["tailf-ned-cisco-ios:aaa"]["accounting"]["exec"]

    return acc_method

def set_accounting_event(oc_system_aaa_accounting, config_leftover, accounting_dict):
    acc_event = {"openconfig-system:event": []}
    acc_event_list = acc_event["openconfig-system:event"]
    # AAA ACCOUNTING EVENT-TYPE AND RECORD
    if accounting_dict.get("commands"):
        for key in accounting_dict.get("commands"):
            if key.get("level") == 15 and key.get("name") == 'default':
                event_type = 'AAA_ACCOUNTING_EVENT_COMMAND'
                if key.get("action-type") == 'stop-only':
                    action = 'STOP'
                elif key.get("action-type") == 'start-stop':
                    action = "START_STOP"
                temp_event = {"openconfig-system:event-type": f'{event_type}',
                            "openconfig-system:config": {
                                "openconfig-system:event-type": f'{event_type}',
                                "openconfig-system:record": f'{action}'
                            }}
                acc_event_list.append(temp_event)
    if accounting_dict.get("exec"):
        for key in accounting_dict.get("exec"):
            if key.get("name") == 'default':
                event_type = 'AAA_ACCOUNTING_EVENT_LOGIN'
                if key.get("action-type") == 'stop-only':
                    action = 'STOP'
                elif key.get("action-type") == 'start-stop':
                    action = "START_STOP"
                temp_event = {"openconfig-system:event-type": f'{event_type}',
                            "openconfig-system:config": {
                                "openconfig-system:event-type": f'{event_type}',
                                "openconfig-system:record": f'{action}'
                            }}
                acc_event_list.append(temp_event)

    return acc_event

def set_authorization_event(oc_system_aaa_authorization, config_leftover, authorization_dict):
    autho_event = {"openconfig-system:event": []}
    autho_event_list = autho_event["openconfig-system:event"]
    # AAA AUTHORIZATION EVENT-TYPE AND RECORD
    if authorization_dict.get("commands"):
        for key in authorization_dict.get("commands"):
            if key.get("level") == 15 and key.get("name") == 'default':
                event_type = 'AAA_AUTHORIZATION_EVENT_COMMAND'
                temp_event = {"openconfig-system:event-type": f'{event_type}',
                            "openconfig-system:config": {
                                "openconfig-system:event-type": f'{event_type}'
                            }}
                autho_event_list.append(temp_event)
        del config_leftover["tailf-ned-cisco-ios:aaa"]["authorization"]["commands"]
    if authorization_dict.get("exec"):
        for key in authorization_dict.get("exec"):
            if key.get("name") == 'default':
                event_type = 'AAA_AUTHORIZATION_EVENT_CONFIG'
                temp_event = {"openconfig-system:event-type": f'{event_type}',
                            "openconfig-system:config": {
                                "openconfig-system:event-type": f'{event_type}'
                            }}
                autho_event_list.append(temp_event)
        del config_leftover["tailf-ned-cisco-ios:aaa"]["authorization"]["exec"]

    return autho_event

def set_authorization_method(oc_system_aaa_authorization, config_leftover, authorization_dict):
    # AAA AUTHORIZATION GROUPS
    autho_method = {"openconfig-system:authorization-method": []}
    autho_method_list = autho_method["openconfig-system:authorization-method"]
    group = group2 = group3 = None

    if authorization_dict.get("commands"):
        for i, command in enumerate(authorization_dict.get("commands")):
            if command.get("tacacsplus"):
                group = 'TACACS_ALL'
            autho_method_list.append(group)
            if command.get("local"):
                group = 'LOCAL'
            autho_method_list.append(group)
            if command.get("group"):
                if command.get("group") == 'tacacs+':
                    group = 'TACACS_ALL'
                else:
                    group = command.get("group")
                autho_method_list.append(group)
            if command.get("group2") and command.get("group2", {}).get("group"):
                if command.get("group2", {}).get("group") == 'tacacs+':
                    group2 = 'TACACS_ALL'
                elif command.get("group2", {}).get("group"):
                    group2 = command.get("group2", {}).get("group")
                autho_method_list.append(group2)
            if command.get("group3") and command.get("group3", {}).get("group"):
                if command.get("group2", {}).get("group") and command.get("group3", {}).get("group") == 'tacacs+':
                    group3 = 'TACACS_ALL'
                elif command.get("group2", {}).get("group") and command.get("group3", {}).get("group"):
                    group3 = command.get("group3", {}).get("group")
                autho_method_list.append(group3)
    if authorization_dict.get("exec"):
        for i, exe in enumerate(authorization_dict.get("exec")):
            if exe.get("tacacsplus"):
                group = 'TACACS_ALL'
            autho_method_list.append(group)
            if exe.get("local"):
                group = 'LOCAL'
            autho_method_list.append(group)
            if exe.get("group"):
                if exe.get("group") == 'tacacs+':
                    group = 'TACACS_ALL'
                else:
                    group = exe.get("group")
                autho_method_list.append(group)
            if exe.get("group2") and exe.get("group2", {}).get("group"):
                if exe.get("group2", {}).get("group") == 'tacacs+':
                    group2 = 'TACACS_ALL'
                elif exe.get("group2", {}).get("group"):
                    group2 = exe.get("group2", {}).get("group")
                autho_method_list.append(group2)
            if exe.get("group3") and exe.get("group3", {}).get("group"):
                if exe.get("group2", {}).get("group") and exe.get("group3", {}).get("group") == 'tacacs+':
                    group3 = 'TACACS_ALL'
                elif exe.get("group2", {}).get("group") and exe.get("group3", {}).get("group"):
                    group3 = exe.get("group3", {}).get("group")
                autho_method_list.append(group3)
    return autho_method

def set_authentication_method(oc_system_aaa_authentication, config_leftover, authentication_dict):
    # AAA AUTHENTICATION GROUPS
    authe_method = {"openconfig-system:authentication-method": []}
    authe_method_list = authe_method["openconfig-system:authentication-method"]
    group = group2 = group3 = None

    if authentication_dict:
        if authentication_dict.get("login"):
            for i, login in enumerate(authentication_dict.get("login")):
                if login.get("local"):
                    group = 'LOCAL'
                authe_method_list.append(group)
                if login.get("tacacsplus"):
                    group = 'TACACS_ALL'
                authe_method_list.append(group)
                if login.get("group"):
                    if login.get("group") == 'tacacs+':
                        group = 'TACACS_ALL'
                    else:
                        group = login.get("group")
                    authe_method_list.append(group)
                if login.get("group2") and login.get("group2", {}).get("group"):
                    if login.get("group2", {}).get("group") == 'tacacs+':
                        group2 = 'TACACS_ALL'
                    elif login.get("group2", {}).get("group"):
                        group2 = login.get("group2", {}).get("group")
                    authe_method_list.append(group2)
                if login.get("group3") and login.get("group3", {}).get("group"):
                    if login.get("group2", {}).get("group") and login.get("group3", {}).get("group") == 'tacacs+':
                        group3 = 'TACACS_ALL'
                    elif login.get("group2", {}).get("group") and login.get("group3", {}).get("group"):
                        group3 = login.get("group3", {}).get("group")
                    authe_method_list.append(group3)
            del config_leftover["tailf-ned-cisco-ios:aaa"]["authentication"]["login"]

    return authe_method

def set_authentication_admin(oc_system_aaa_authentication, config_leftover, authentication_user_list):
    authe_admin = {"openconfig-system:config": {}}
    authe_admin_dict = authe_admin["openconfig-system:config"]
    pwd = pwd_hashed = ssh_key = None
    temp_user = {}
    # AAA AUTHENTICATION ADMIN-USER
    if authentication_user_list:
        for i, user in enumerate(authentication_user_list):
            if "admin" in user.get("name"):
                pwd_hashed = user.get("secret", {}).get("secret")
                temp_user = {"openconfig-system:admin-password": 'admin',
                                "openconfig-system:admin-password-hashed": f'{pwd_hashed}'
                            }
                config_leftover["tailf-ned-cisco-ios:username"][i] = None
        authe_admin_dict.update(temp_user)
    return authe_admin

def set_authentication_user(oc_system_aaa_authentication, config_leftover, authentication_user_list):
    authe_user = {"openconfig-system:user": []}
    authe_user_list = authe_user["openconfig-system:user"]
    pwd = pwd_hashed = ssh_key = None
    # AAA AUTHENTICATION USERS
    if authentication_user_list:
        for i, user in enumerate(authentication_user_list):
            if "admin" not in user.get("name"):
                role = 'SYSTEM_ROLE_ADMIN'
                pwd = user.get("secret", {}).get("secret")
                temp_user = {"openconfig-system:username": f'{user.get("name")}',
                            "openconfig-system:config": {
                                "openconfig-system:username": f'{user.get("name")}',
                                "openconfig-system:password": f'{pwd}',
                                "openconfig-system:password-hashed": f'{pwd_hashed}', # TODO
                                "openconfig-system:role": f'{role}',
                                "openconfig-system:ssh-key:": f'{ssh_key}' # TODO
                            }}
                authe_user_list.append(temp_user)
                config_leftover["tailf-ned-cisco-ios:username"][i] = None

    return authe_user

def cleanup_server_access(config_leftover, group_access_type, access_type):
    if len(config_leftover.get("tailf-ned-cisco-ios:aaa", {}).get("group", {}).get("server", {}).get(group_access_type, [])) < 1:
        return

    updated_server_list = []

    for group_access_type_server in config_leftover["tailf-ned-cisco-ios:aaa"]["group"]["server"][group_access_type]:
        updated_server_names = []

        for name in group_access_type_server.get("server", {}).get("name", []):
            if name and name.get("name"):
                updated_server_names.append(name)

        if len(updated_server_names) > 0:
            group_access_type_server["server"]["name"] = updated_server_names
        elif "name" in group_access_type_server.get("server", {}):
            del group_access_type_server["server"]["name"]

    for server in config_leftover.get(f"tailf-ned-cisco-ios:{access_type}", {}).get("server", []):
        if server and len(server) > 0:
            updated_server_list.append(server)

    if len(updated_server_list) > 0:
        config_leftover[f"tailf-ned-cisco-ios:{access_type}"]["server"] = updated_server_list
    elif "server" in config_leftover.get(f"tailf-ned-cisco-ios:{access_type}", {}):
        del config_leftover[f"tailf-ned-cisco-ios:{access_type}"]["server"]

def xe_system_logging(config_before: dict, config_leftover: dict, if_ip: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System Logging
    """
    oc_system_logging_console = openconfig_system["openconfig-system:system"]["openconfig-system:logging"]["openconfig-system:console"]
    oc_system_logging_monitor = openconfig_system["openconfig-system:system"]["openconfig-system:logging"]["openconfig-system-ext:terminal-monitor"]
    oc_system_logging = openconfig_system["openconfig-system:system"]["openconfig-system:logging"]
    oc_system_archive = openconfig_system["openconfig-system:system"]["openconfig-system-ext:services"]
    logging_console = config_before.get("tailf-ned-cisco-ios:logging", {}).get("console")
    logging_monitor = config_before.get("tailf-ned-cisco-ios:logging", {}).get("monitor")
    logging = config_before.get("tailf-ned-cisco-ios:logging")
    archive = config_before.get("tailf-ned-cisco-ios:archive")
    intf_ip_name_dict = common.xe_system_get_interface_ip_address(config_before)

    # LOGGING BUFFERED
    if logging.get("buffered"):
        temp_logging_buffered = {
            "openconfig-system-ext:buffered": set_logging_buffered(logging, config_leftover, oc_system_logging)
        }
        oc_system_logging.update(temp_logging_buffered)
        del config_leftover["tailf-ned-cisco-ios:logging"]["buffered"]["severity-level"]
        if logging.get("buffered", {}).get("buffer-size"):
            del config_leftover["tailf-ned-cisco-ios:logging"]["buffered"]["buffer-size"]
    else:
        temp_logging_buffered = {
            "openconfig-system-ext:buffered": {"openconfig-system-ext:config": {
                "openconfig-system-ext:enabled": False
            }}}
        oc_system_logging.update(temp_logging_buffered)

    # LOGGING CONSOLE
    if logging_console:
        temp_logging_console = {
            "openconfig-system:config": {"openconfig-system-ext:enabled": True},
            "openconfig-system:selectors": set_logging_console(logging_console,
                                                                config_leftover,
                                                                oc_system_logging_console),
        }
        oc_system_logging_console.update(temp_logging_console)
        del config_leftover["tailf-ned-cisco-ios:logging"]["console"]["severity-level"]
    else:
        temp_logging_console = {
            "openconfig-system:config": {"openconfig-system-ext:enabled": False}
        }
        oc_system_logging_console.update(temp_logging_console)

    # LOGGING MONITOR
    if logging_monitor:
        temp_logging_monitor = {
            "openconfig-system-ext:selectors": set_logging_monitor(logging_monitor,
                                                                    config_leftover,
                                                                    oc_system_logging_monitor),
        }
        oc_system_logging_monitor.update(temp_logging_monitor)
        del config_leftover["tailf-ned-cisco-ios:logging"]["monitor"]["severity-level"]

    # LOGGING HOST
    if logging.get("host"):
        temp_logging_host = {
            "openconfig-system:remote-servers": set_logging_host(logging, config_leftover,
                                                                oc_system_logging, if_ip,
                                                                intf_ip_name_dict),
        }
        oc_system_logging.update(temp_logging_host)

def set_logging_buffered(logging, config_leftover, oc_system_logging):
    buffered = {"openconfig-system-ext:config": []}
    buffered_list = buffered["openconfig-system-ext:config"]
    # LOGGING BUFFERED SEVERITY AND BUFFER SIZE
    buffer_size = 4096 # Default Buffer Size
    severity = "DEBUG" # Default Severity
    if logging.get("buffered", {}).get("buffer-size"):
        buffer_size = logging["buffered"]["buffer-size"]
    if logging.get("buffered", {}).get("severity-level"):
        # SEVERITY
        severity = get_severity(logging["buffered"]["severity-level"])
        temp_buffered = {"openconfig-system-ext:enabled": True,
                    "openconfig-system-ext:severity": f'{severity}',
                    "openconfig-system-ext:buffer-size": f'{buffer_size}'
                    }
        buffered_list.append(temp_buffered)

    return buffered

def set_logging_console(logging_console, config_leftover, oc_system_logging_console):
    console = {"openconfig-system:selector": []}
    console_list = console["openconfig-system:selector"]
    # LOGGING CONSOLE FACILITY AND SEVERITY
    severity = "DEBUG" # Default Severity
    if logging_console.get("severity-level"):
        # SEVERITY
        severity = get_severity(logging_console["severity-level"])
        temp_console = {"openconfig-system:facility": "SYSLOG",
                    "openconfig-system:severity": f'{severity}',
                    "openconfig-system:config": {
                        "openconfig-system:facility": "SYSLOG",
                        "openconfig-system:severity": f'{severity}'
                    }}
        console_list.append(temp_console)

    return console

def set_logging_monitor(logging_monitor, config_leftover, oc_system_logging_monitor):
    monitor = {"openconfig-system-ext:selector": []}
    monitor_list = monitor["openconfig-system-ext:selector"]
    # LOGGING MONITOR FACILITY AND SEVERITY
    severity = "DEBUG" # Default Severity
    if logging_monitor.get("severity-level"):
        # SEVERITY
        severity = get_severity(logging_monitor["severity-level"])
        temp_monitor = {"openconfig-system-ext:facility": "SYSLOG",
                    "openconfig-system-ext:severity": f'{severity}',
                    "openconfig-system-ext:config": {
                        "openconfig-system-ext:facility": "SYSLOG",
                        "openconfig-system-ext:severity": f'{severity}'
                    }}
        monitor_list.append(temp_monitor)

    return monitor

def set_logging_host(logging, config_leftover, oc_system_logging, if_ip, intf_ip_name_dict):
    hosts = {"openconfig-system:remote-server": []}
    hosts_list = hosts["openconfig-system:remote-server"]
    # LOGGING HOST IP, PORT, VRF, SOURCE ADDRESS
    host_ipv4 = logging.get("host", {}).get('ipv4')
    host_ipv4_vrf = logging.get("host", {}).get('ipv4-vrf')
    source_intf = logging.get("source-interface")
    vrf_source_intf_list = vrf_source_ip_list = []
    severity = "INFORMATIONAL" # Default Severity

    # SEVERITY
    if logging.get("trap"):
        severity = get_severity(logging["trap"])

    # GET SOURCE INTERFACE AND VRF
    for index, int_vrf in enumerate(source_intf):
        if "vrf" in int_vrf.keys():
            temp_intf_vrf = {int_vrf["vrf"]: int_vrf["name"]}
            vrf_source_intf_list.append(temp_intf_vrf)
        else:
            temp_intf_vrf = {"default": int_vrf["name"]}
            vrf_source_intf_list.append(temp_intf_vrf)
        if config_leftover.get("tailf-ned-cisco-ios:logging", {}).get("source-interface", [])[index].get("name"):
            config_leftover["tailf-ned-cisco-ios:logging"]["source-interface"][index]["name"] = None
        if config_leftover.get("tailf-ned-cisco-ios:logging", {}).get("source-interface", [])[index].get("vrf"):
            config_leftover["tailf-ned-cisco-ios:logging"]["source-interface"][index]["vrf"] = None

    # ADD HOST IPV4
    if host_ipv4:
        for index, host_info in enumerate(host_ipv4):
            host = host_info.get("host")
            host_vrf = "default"
            source_ip = "1.1.1.1" # Placeholder Source IPv4
            intf = "GigabitEthernet1" # Placeholder Source Interface
            if logging.get("source-interface"):
                for vrf_info in vrf_source_intf_list:
                    if vrf_info.get("default"):
                        intf = vrf_info.get("default")
                        break
                if intf_ip_name_dict.get(intf):
                    source_ip = intf_ip_name_dict.get(intf)

            temp_host = {"openconfig-system:host": f'{host}',
                        "openconfig-system:config": get_host(host, source_ip, host_vrf),
                        "openconfig-system:selectors": {
                            "openconfig-system:selector": get_facility_severity(severity)
                        }}
            hosts_list.append(temp_host)
            config_leftover["tailf-ned-cisco-ios:logging"]["host"]["ipv4"][index]["host"] = None

    # ADD HOST IPV4 AND VRF
    if host_ipv4_vrf:
        for index, host_info in enumerate(host_ipv4_vrf):
            host = host_info.get("host")
            host_vrf = host_info.get("vrf")
            source_ip_vrf = "1.1.1.1" # Placeholder Source IPv4
            intf_vrf = "GigabitEthernet1" # Placeholder Source Interface
            if logging.get("source-interface"):
                for vrf_info in vrf_source_intf_list:
                    if vrf_info.get(host_vrf):
                        intf_vrf = vrf_info.get(host_vrf)
                        break
                if intf_ip_name_dict.get(intf_vrf):
                    source_ip_vrf = intf_ip_name_dict.get(intf_vrf)

            temp_host = {"openconfig-system:host": f'{host}',
                        "openconfig-system:config": get_host(host, source_ip_vrf, host_vrf),
                        "openconfig-system:selectors": {
                            "openconfig-system:selector": get_facility_severity(severity)
                        }}
            hosts_list.append(temp_host)
            config_leftover["tailf-ned-cisco-ios:logging"]["host"]["ipv4-vrf"][index]["host"] = None
            config_leftover["tailf-ned-cisco-ios:logging"]["host"]["ipv4-vrf"][index]["vrf"] = None

    if logging.get("facility"):
        del config_leftover["tailf-ned-cisco-ios:logging"]["facility"]
    if logging.get("trap"):
        del config_leftover["tailf-ned-cisco-ios:logging"]["trap"]
    cleanup_logging(config_leftover)
    return hosts

def get_severity(logging_severity):
    # GET LOGGING SEVERITY
    if logging_severity == "emergencies" or logging_severity == 0:
        severity = "EMERGENCY"
    elif logging_severity == "alerts" or logging_severity == 1:
        severity = "ALERT"
    elif logging_severity == "critical" or logging_severity == 2:
        severity = "CRITICAL"
    elif logging_severity == "errors" or logging_severity == 3:
        severity = "ERROR"
    elif logging_severity == "warnings" or logging_severity == 4:
        severity = "WARNING"
    elif logging_severity == "notifications" or logging_severity == 5:
        severity = "NOTICE"
    elif logging_severity == "informational" or logging_severity == 6:
        severity = "INFORMATIONAL"
    elif logging_severity == "debugging" or logging_severity == 7:
        severity = "DEBUG"

    return severity

def get_host(host, source_ip, host_vrf):
    # GET HOST, VRF AND SOURCE IP ADDRESS
    temp_host = {"openconfig-system:host": f'{host}',
                    "openconfig-system:remote-port": 514,
                    "openconfig-system:source-address": f'{source_ip}',
                    "openconfig-system-ext:use-vrf": f'{host_vrf}'
                }

    return temp_host

def get_facility_severity(severity):
    # GET FACILITY AND SEVERITY
    temp_fac_sev = [{"openconfig-system:facility": "SYSLOG",
                        "openconfig-system:severity": f'{severity}',
                        "openconfig-system:config": {
                        "openconfig-system:facility": "SYSLOG",
                        "openconfig-system:severity": f'{severity}'
                    }}]

    return temp_fac_sev

def cleanup_logging(config_leftover):
    if len(config_leftover.get("tailf-ned-cisco-ios:logging", {}).get("source-interface", [])) >= 1:
        updated_source_intf = []

        for source in config_leftover["tailf-ned-cisco-ios:logging"]["source-interface"]:
            if source and source.get("name"):
                updated_source_intf.append(source)

        if len(updated_source_intf) > 0:
            config_leftover["tailf-ned-cisco-ios:logging"]["source-interface"] = updated_source_intf
        elif "name" not in config_leftover.get("tailf-ned-cisco-ios:logging", {}).get("source-interface"):
            del config_leftover["tailf-ned-cisco-ios:logging"]["source-interface"]

    if len(config_leftover.get("tailf-ned-cisco-ios:logging", {}).get("host", {}).get("ipv4", [])) >= 1:
        updated_ipv4 = []

        for host_ipv4 in config_leftover["tailf-ned-cisco-ios:logging"]["host"]["ipv4"]:
            if host_ipv4 and host_ipv4.get("host"):
                updated_ipv4.append(host_ipv4)

        if len(updated_ipv4) > 0:
            config_leftover["tailf-ned-cisco-ios:logging"]["host"]["ipv4"] = updated_ipv4
        elif "host" not in config_leftover.get("tailf-ned-cisco-ios:logging", {}).get("host", {}).get("ipv4"):
            del config_leftover["tailf-ned-cisco-ios:logging"]["host"]["ipv4"]

    if len(config_leftover.get("tailf-ned-cisco-ios:logging", {}).get("host", {}).get("ipv4-vrf", [])) >= 1:
        updated_ipv4_vrf = []

        for host_ipv4_vrf in config_leftover["tailf-ned-cisco-ios:logging"]["host"]["ipv4-vrf"]:
            if host_ipv4_vrf and host_ipv4_vrf.get("host"):
                updated_ipv4_vrf.append(host_ipv4_vrf)

        if len(updated_ipv4_vrf) > 0:
            config_leftover["tailf-ned-cisco-ios:logging"]["host"]["ipv4-vrf"] = updated_ipv4_vrf
        elif "host" not in config_leftover.get("tailf-ned-cisco-ios:logging", {}).get("host", {}).get("ipv4-vrf"):
            del config_leftover["tailf-ned-cisco-ios:logging"]["host"]["ipv4-vrf"]

def xe_system_clock_timezone(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System Clock Timezone
    """
    openconfig_system_clock_config = openconfig_system["openconfig-system:system"][
        "openconfig-system:clock"]["openconfig-system:config"]
    timezone_name = ["UTC", "0", "0"] # Placeholder Timezone, Hours and Minutes
    zone = config_before.get("tailf-ned-cisco-ios:clock", {}).get("timezone", {}).get("zone")
    hours = config_before.get("tailf-ned-cisco-ios:clock", {}).get("timezone", {}).get("hours")
    minutes = config_before.get("tailf-ned-cisco-ios:clock", {}).get("timezone", {}).get("minutes")

    if zone and len(zone) == 3:
        timezone_name[0] = zone
        del config_leftover["tailf-ned-cisco-ios:clock"]["timezone"]["zone"]

    if hours != None:
        timezone_name[1] = f'{hours}'
        del config_leftover["tailf-ned-cisco-ios:clock"]["timezone"]["hours"]

    if minutes != None:
        timezone_name[2] = f'{minutes}'
        del config_leftover["tailf-ned-cisco-ios:clock"]["timezone"]["minutes"]

    openconfig_system_clock_config["openconfig-system:timezone-name"] = ' '.join(timezone_name)

    # Clean up clock remaining
    if type(config_leftover.get("tailf-ned-cisco-ios:clock", {}).get("timezone", "")) is dict and len(config_leftover.get("tailf-ned-cisco-ios:clock", {}).get("timezone")) == 0:
        del config_leftover["tailf-ned-cisco-ios:clock"]["timezone"]
    if type(config_leftover.get("tailf-ned-cisco-ios:clock", "")) is dict and len(
            config_leftover.get("tailf-ned-cisco-ios:clock")) == 0:
        del config_leftover["tailf-ned-cisco-ios:clock"]


def xe_system_timestamps(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System Timestamps
    """
    oc_system_timestamps = openconfig_system["openconfig-system:system"]["openconfig-system-ext:timestamps"]
    timestamps = config_before.get("tailf-ned-cisco-ios:service", {}).get("timestamps")
    debug = config_before.get("tailf-ned-cisco-ios:service", {}).get("timestamps", {}).get("debug")
    log = config_before.get("tailf-ned-cisco-ios:service", {}).get("timestamps", {}).get("log")

    # TIMESTAMPS DEBUG
    if debug:
        temp_timestamps_debug = {"openconfig-system-ext:debugging": set_timestamps(debug, config_leftover, timestamps)}
        oc_system_timestamps.update(temp_timestamps_debug)
        if "debug" in timestamps and "datetime" in timestamps["debug"]:
            if "msec" in timestamps["debug"]["datetime"]:
                del config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["debug"]["datetime"]["msec"]
            if "localtime" in timestamps["debug"]["datetime"]:
                del config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["debug"]["datetime"]["localtime"]
            if len(config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["debug"]["datetime"]) == 0:
                del config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["debug"]["datetime"]
        elif "debug" in timestamps and "uptime" in timestamps["debug"]:
            del config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["debug"]["uptime"]
        if len(config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["debug"]) == 0:
            del config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["debug"]
    # TIMESTAMPS LOG
    if log:
        temp_timestamps_log = {"openconfig-system-ext:logging": set_timestamps(log, config_leftover, timestamps)}
        oc_system_timestamps.update(temp_timestamps_log)
        if "log" in timestamps and "datetime" in timestamps["log"]:
            if "msec" in timestamps["log"]["datetime"]:
                del config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["log"]["datetime"]["msec"]
            if "localtime" in timestamps["log"]["datetime"]:
                del config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["log"]["datetime"]["localtime"]
            if len(config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["log"]["datetime"]) == 0:
                del config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["log"]["datetime"]
        elif "log" in timestamps and "uptime" in timestamps["log"]:
            del config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["log"]["uptime"]
        if len(config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["log"]) == 0:
            del config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]["log"]
    # Clean up timestamps
    if (config_leftover["tailf-ned-cisco-ios:service"].get("timestamps")
        and len(config_leftover["tailf-ned-cisco-ios:service"].get("timestamps")) == 0):
        del config_leftover["tailf-ned-cisco-ios:service"]["timestamps"]


def set_timestamps(service, config_leftover, timestamps):
    datetime = uptime = localtime = False # Initialize variables
    if type(service.get("datetime", "")) is dict:
        datetime = True
    if type(service.get("datetime", {}).get("localtime", '')) is list:
        localtime = True
    if type(service.get("uptime", '')) is list:
        uptime = True

    temp_timestamps = {"openconfig-system-ext:config": {
                            "openconfig-system-ext:enabled": True,
                            "openconfig-system-ext:datetime": datetime,
                            "openconfig-system-ext:uptime": uptime,
                            "openconfig-system-ext:localtime": localtime
                        }}

    return temp_timestamps

def xe_system_name_server(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System DNS
    """
    oc_system_dns = openconfig_system["openconfig-system:system"]["openconfig-system:dns"]
    name_server = config_before.get("tailf-ned-cisco-ios:ip", {}).get("name-server")
    name_server_list = config_before.get("tailf-ned-cisco-ios:ip", {}).get("name-server", {}).get("name-server-list")
    vrf_list = config_before.get("tailf-ned-cisco-ios:ip", {}).get("name-server", {}).get("vrf")

    if name_server:
        temp_server_list = {"openconfig-system:servers": set_server_list(name_server_list,
            vrf_list, config_leftover)}
        oc_system_dns.update(temp_server_list)

def set_server_list(name_server_list, vrf_list, config_leftover):
    svr = {"openconfig-system:server": []}
    svr_list = svr["openconfig-system:server"]
    # LIST OF VRF AND DNS SERVERS
    if (vrf_list):
        for index_vrf, vrf in enumerate(vrf_list):
            server_list_vrf = vrf.get("name-server-list")
            for index_server, server in enumerate(server_list_vrf):
                temp_svr = {"openconfig-system:address": server["address"],
                        "openconfig-system:config": {
                            "openconfig-system:address": server["address"],
                            "openconfig-system:port": 53, # Always 53 for IOS
                            "openconfig-system-ext:use-vrf": vrf["name"]
                        }}
                svr_list.append(temp_svr)
                config_leftover["tailf-ned-cisco-ios:ip"]["name-server"]["vrf"][index_vrf][
                    "name"] = None
    # LIST OF DNS SERVERS
    if (name_server_list) and "vrf" not in name_server_list:
        for index_server, server in enumerate(name_server_list):
            temp_svr = {"openconfig-system:address": server["address"],
                    "openconfig-system:config": {
                        "openconfig-system:address": server["address"],
                        "openconfig-system:port": 53 # Always 53 for IOS
                    }}
            svr_list.append(temp_svr)
            config_leftover["tailf-ned-cisco-ios:ip"]["name-server"]["name-server-list"][
                index_server]["address"] = None

    cleanup_name_server(config_leftover, name_server_list, vrf_list)
    return svr

def cleanup_name_server(config_leftover, name_server_list, vrf_list):
    if name_server_list and len(config_leftover.get("tailf-ned-cisco-ios:ip", {}).get(
        "name-server", {}).get("name-server-list")) >= 1:
        updated_name_server = []

        for server in config_leftover["tailf-ned-cisco-ios:ip"]["name-server"][
            "name-server-list"]:
            if server and server.get("address"):
                updated_name_server.append(server)

        if len(updated_name_server) > 0:
            config_leftover["tailf-ned-cisco-ios:ip"]["name-server"]["name-server-list"] = updated_name_server
        elif "address" not in config_leftover.get("tailf-ned-cisco-ios:ip", {}).get(
            "name-server").get("name-server-list"):
            del config_leftover["tailf-ned-cisco-ios:ip"]["name-server"]["name-server-list"]

    if vrf_list and len(config_leftover.get("tailf-ned-cisco-ios:ip", {}).get("name-server", {}).get(
        "vrf")) >= 1:
        updated_vrf = []

        for vrf in config_leftover["tailf-ned-cisco-ios:ip"]["name-server"]["vrf"]:
            if vrf and vrf.get("name"):
                updated_vrf.append(vrf)

        if len(updated_vrf) > 0:
            config_leftover["tailf-ned-cisco-ios:ip"]["name-server"]["vrf"] = updated_vrf
        elif "name" not in config_leftover.get("tailf-ned-cisco-ios:ip", {}).get("name-server").get(
            "vrf"):
            del config_leftover["tailf-ned-cisco-ios:ip"]["name-server"]["vrf"]

def xe_system_nat(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig System NAT
    """
    oc_system_nat = openconfig_system["openconfig-system:system"]["openconfig-system-ext:services"][
        "openconfig-system-ext:nat"]
    oc_system_inside_source = openconfig_system["openconfig-system:system"]["openconfig-system-ext:services"][
        "openconfig-system-ext:nat"]["openconfig-system-ext:inside"]["openconfig-system-ext:source"]
    nat_pool = config_before.get("tailf-ned-cisco-ios:ip", {}).get("nat", {}).get("pool")
    nat_inside_source = config_before.get("tailf-ned-cisco-ios:ip", {}).get("nat", {}).get("inside", {}).get("source")
    
    if nat_pool:
        temp_nat_pool_list = {"openconfig-system-ext:pools": set_nat_pool(nat_pool, config_leftover)}
        oc_system_nat.update(temp_nat_pool_list)

    if nat_inside_source:
        temp_nat_inside_source_list = {"openconfig-system-ext:local-addresses-access-lists": set_nat_inside(nat_inside_source, config_leftover)}
        oc_system_inside_source.update(temp_nat_inside_source_list)

def set_nat_pool(nat_pool, config_leftover):
    pool_config = {"openconfig-system-ext:pool": []}
    pool_config_list = pool_config["openconfig-system-ext:pool"]
    # LIST OF NAT POOLS
    for index, pool in enumerate(nat_pool):
        start_address = end_address = "0.0.0.0" # Initialize variables
        if pool.get("start-address"):
            start_address = pool["start-address"]
        if pool.get("end-address"):
            end_address = pool["end-address"]
        if pool.get("prefix-length"):
            temp_pool = {"openconfig-system-ext:name": f'{pool.get("id")}',
                        "openconfig-system-ext:config": {
                            "openconfig-system-ext:name": f'{pool.get("id")}',
                            "openconfig-system-ext:start-address": start_address,
                            "openconfig-system-ext:end-address": end_address,
                            "openconfig-system-ext:prefix-length": f'{pool.get("prefix-length")}'
                        }}
            pool_config_list.append(temp_pool)
        elif pool.get("netmask"):
            temp_pool = {"openconfig-system-ext:name": f'{pool.get("id")}',
                        "openconfig-system-ext:config": {
                            "openconfig-system-ext:name": f'{pool.get("id")}',
                            "openconfig-system-ext:start-address": start_address,
                            "openconfig-system-ext:end-address": end_address,
                            "openconfig-system-ext:netmask": f'{pool.get("netmask")}'
                        }}
            pool_config_list.append(temp_pool)

    del config_leftover["tailf-ned-cisco-ios:ip"]["nat"]["pool"]
    return pool_config

def set_nat_inside(nat_inside_source, config_leftover):
    nat_inside = {"openconfig-system-ext:local-addresses-access-list": []}
    nat_inside_list = nat_inside["openconfig-system-ext:local-addresses-access-list"]
    # LIST OF NAT ACLs
    for inside_source in nat_inside_source.get("list", []):
        overload = False  # Initialize variable
        if "overload" in inside_source:
            overload = True
        temp_nat_inside = {"openconfig-system-ext:local-addresses-access-list-name": f'{inside_source.get("id")}',
                           "openconfig-system-ext:config": {
                               "openconfig-system-ext:local-addresses-access-list-name": f'{inside_source.get("id")}',
                               "openconfig-system-ext:global-interface-name": f'{inside_source.get("interface")}',
                               "openconfig-system-ext:overload": overload
                           }}
        nat_inside_list.append(temp_nat_inside)
    # LIST OF NAT ACLs WITH VRF
    for inside_source in nat_inside_source.get("list-vrf", {}).get("list", []):
        overload = False  # Initialize variable
        if "overload" in inside_source:
            overload = True
        temp_nat_inside = {"openconfig-system-ext:local-addresses-access-list-name": f'{inside_source.get("id")}',
                           "openconfig-system-ext:config": {
                               "openconfig-system-ext:local-addresses-access-list-name": f'{inside_source.get("id")}',
                               "openconfig-system-ext:vrf": f'{inside_source.get("vrf")}',
                               "openconfig-system-ext:overload": overload
                           }}
        if inside_source.get("pool"):
            temp_nat_inside["openconfig-system-ext:config"][
                "openconfig-system-ext:global-pool-name"] = inside_source.get("pool")
        if inside_source.get("interface"):
            temp_nat_inside["openconfig-system-ext:config"][
                "openconfig-system-ext:global-interface-name"] = inside_source.get("interface")
        nat_inside_list.append(temp_nat_inside)
    del config_leftover["tailf-ned-cisco-ios:ip"]["nat"]["inside"]
    return nat_inside


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
    # xe_system_aaa(before, leftover, if_ip)
    xe_system_logging(before, leftover, if_ip)
    xe_system_clock_timezone(before, leftover)
    xe_system_timestamps(before, leftover)
    xe_system_name_server(before, leftover)
    xe_system_nat(before, leftover)
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
