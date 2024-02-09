#! /usr/bin/env python3
"""
Translate NSO Device config to MDD OpenConfig

This script will pull a device's configuration from an NSO server, convert the NED structured configuration to
MDD OpenConfig, save the NSO configuration to a file named {device_name}_configuration.json, save the NSO device
configuration minus parts replaced by OpenConfig to a file named {device_name}_configuration_remaining.json,
and save the MDD OpenConfig configuration to a file named {nso_device}_openconfig_qos.json.

The script requires the following environment variables:
NSO_URL - URL for the NSO server
NSO_USERNAME
NSO_PASSWORD
NSO_DEVICE - NSO device name for configuration translation
TEST - True or False. True enables sending the OpenConfig to the NSO server after generation
"""

import sys
# from pathlib import Path
from importlib.util import find_spec
qos_notes = []

dscp_dict = {'cs1':8, 'af11':10, 'af12':12, 'af13':14, 'cs2':16, 'af21':18, 'af22':20, 
             'af23':22, 'cs3':24, 'af31':26, 'af32':28, 'af33':30, 'cs4':32, 'af41':34,
             'af42':36, 'af43':38, 'cs5':40, 'ef':46, 'cs6':48, 'cs7':56, 'default':0}

openconfig_qos = {
    "openconfig-qos:qos": {
        "openconfig-qos:forwarding-groups": {
            "openconfig-qos:forwarding-group": []
        },
        "openconfig-qos:classifiers": {
            "openconfig-qos:classifier": []
        },
        "openconfig-qos:scheduler-policies": {
            "openconfig-qos:scheduler-policy": []
        },
        "openconfig-qos:interfaces": {
            "openconfig-qos:interface": []
        }
    }
}


def configure_xe_qos(config_before: dict, config_leftover: dict) -> None:
    """
    Translates NSO XE NED to MDD OpenConfig QoS
    """
    openconfig_policy_map = openconfig_qos["openconfig-qos:qos"]["openconfig-qos:forwarding-groups"]["openconfig-qos:forwarding-group"]
    openconfig_class_map = openconfig_qos["openconfig-qos:qos"]["openconfig-qos:classifiers"]["openconfig-qos:classifier"]
    openconfig_scheduler = openconfig_qos["openconfig-qos:qos"]["openconfig-qos:scheduler-policies"]["openconfig-qos:scheduler-policy"]
    openconfig_interface = openconfig_qos["openconfig-qos:qos"]["openconfig-qos:interfaces"]["openconfig-qos:interface"]
    policy_map_list = config_before.get("tailf-ned-cisco-ios:policy-map")
    class_map_list = config_before.get("tailf-ned-cisco-ios:class-map")
    interface_dict = config_before.get("tailf-ned-cisco-ios:interface")

    # Init variables: class default index, class map index
    cd_index = c_index = 0
    # Init list: interface to scheduler list
    intf_to_sched_list = []

    # Configure OC Forwarding Groups and Schedulers
    for policy_map_index, policy_map in enumerate(policy_map_list):
        # Configure OC Forwarding Groups
        set_qos_policy_map(policy_map, openconfig_policy_map)
        # Configure OC Schedulers
        # For Class Default
        if "class-default" in policy_map:
            cd_index += 1
            # Configure OC terms class-default
            set_qos_class_default(cd_index, policy_map, openconfig_class_map)
            # Priority percent and kilo-bits
            if "priority" in policy_map["class-default"]["class"][0]:
                if "percent" in policy_map["class-default"]["class"][0]["priority"]:
                    set_sched_class_default_priority_percent(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler)
                elif "kilo-bits" in policy_map["class-default"]["class"][0]["priority"]:
                    set_sched_class_default_priority_bits(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler)
                intf_to_scheduler_map(config_leftover, policy_map, intf_to_sched_list, openconfig_scheduler)
            # Bandwidth percent and bits
            elif "bandwidth" in policy_map["class-default"]["class"][0]:
                if "percent" in policy_map["class-default"]["class"][0]["bandwidth"]:
                    set_sched_class_default_bandwidth_percent(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler)
                elif "bits" in policy_map["class-default"]["class"][0]:
                    set_sched_class_default_bandwidth_bits(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler)
                intf_to_scheduler_map(config_leftover, policy_map, intf_to_sched_list, openconfig_scheduler)
            # Police CIR
            elif "police-policy-map" in policy_map["class-default"]["class"][0]:
                # Two Rate, Three Color
                if "conform-set-dscp-transmit" in policy_map["class-default"]["class"][0]["police-policy-map"]["police"]["actions"] and ("exceed-set-dscp-transmit" in policy_map[
                    "class-default"]["class"][0]["police-policy-map"]["police"]["actions"] or "exceed-drop" in policy_map["class-default"]["class"][0]["police-policy-map"]["police"]["actions"]) and (
                        "violate-set-dscp-transmit" in policy_map["class-default"]["class"][0][
                        "police-policy-map"]["police"]["actions"] or "violate-drop" in policy_map["class-default"]["class"][0]["police-policy-map"]["police"]["actions"]):
                    set_sched_class_default_policy_three_color(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler)
                # One Rate, Two Color
                elif "conform-set-dscp-transmit" in policy_map["class-default"]["class"][0]["police-policy-map"]["police"]["actions"] and ("exceed-set-dscp-transmit" in policy_map[
                    "class-default"]["class"][0]["police-policy-map"]["police"]["actions"] or "exceed-drop" in policy_map["class-default"]["class"][0]["police-policy-map"]["police"]["actions"]):
                    set_sched_class_default_policy_two_color(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler)
                intf_to_scheduler_map(config_leftover, policy_map, intf_to_sched_list, openconfig_scheduler)
            # Police CIR Percent
            elif "police-cir-percent" in policy_map["class-default"]["class"][0]:
                # Two Rate, Three Color
                if "conform-set-dscp-transmit" in policy_map["class-default"]["class"][0]["police-cir-percent"]["police"]["cir"]["percent"]["actions"] and ("exceed-set-dscp-transmit" in policy_map[
                    "class-default"]["class"][0]["police-cir-percent"]["police"]["cir"]["percent"]["actions"] or "exceed-drop" in policy_map["class-default"]["class"][0]["police-cir-percent"]["police"]["cir"]["percent"]["actions"]) and (
                        "violate-set-dscp-transmit" in policy_map["class-default"]["class"][0]["police-cir-percent"]["police"]["cir"]["percent"]["actions"] or "violate-drop" in policy_map["class-default"][
                            "class"][0]["police-cir-percent"]["police"]["cir"]["percent"]["actions"]):
                    set_sched_class_default_policy_three_color_percent(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler)
                # One Rate, Two Color
                elif "conform-set-dscp-transmit" in policy_map["class-default"]["class"][0]["police-cir-percent"]["police"]["cir"]["percent"]["actions"] and ("exceed-set-dscp-transmit" in policy_map[
                    "class-default"]["class"][0]["police-cir-percent"]["police"]["cir"]["percent"]["actions"] or "exceed-drop" in policy_map["class-default"]["class"][0]["police-cir-percent"]["police"]["cir"]["percent"]["actions"]):
                    set_sched_class_default_policy_two_color_percent(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler)
                intf_to_scheduler_map(config_leftover, policy_map, intf_to_sched_list, openconfig_scheduler)
        #For class-map
        if "class" in policy_map:
            for class_index, class_name in enumerate(policy_map["class"]):
                c_index += 1
                # Priority percent and kilo-bits
                if "priority" in class_name:
                    if "percent" in class_name["priority"]:
                        set_sched_priority_percent(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler)
                    elif "kilo-bits" in class_name["priority"]:
                        set_sched_priority_bits(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler)
                    intf_to_scheduler_map(config_leftover, policy_map, intf_to_sched_list, openconfig_scheduler)
                # Bandwidth percent and bits
                elif "bandwidth" in class_name:
                    if "percent" in class_name["bandwidth"]:
                        set_sched_bandwidth_percent(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler)
                    elif "bits" in class_name["bandwidth"]:
                        set_sched_bandwidth_bits(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler)
                    intf_to_scheduler_map(config_leftover, policy_map, intf_to_sched_list, openconfig_scheduler)
                # Police CIR
                elif "police-policy-map" in class_name:
                    # Two Rate, Three Color
                    if "conform-set-dscp-transmit" in class_name["police-policy-map"]["police"]["actions"] and ("exceed-set-dscp-transmit" in class_name[
                        "police-policy-map"]["police"]["actions"] or "exceed-drop" in class_name["police-policy-map"]["police"]["actions"]) and (
                            "violate-set-dscp-transmit" in class_name["police-policy-map"]["police"][
                            "actions"] or "violate-drop" in class_name["police-policy-map"]["police"]["actions"]):
                        set_sched_policy_three_color(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler)
                    # One Rate, Two Color
                    elif "conform-set-dscp-transmit" in class_name["police-policy-map"]["police"]["actions"] and ("exceed-set-dscp-transmit" in class_name[
                        "police-policy-map"]["police"]["actions"] or "exceed-drop" in class_name["police-policy-map"]["police"]["actions"]):
                        set_sched_policy_two_color(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler)
                    intf_to_scheduler_map(config_leftover, policy_map, intf_to_sched_list, openconfig_scheduler)
                # Police CIR Percent
                elif "police-cir-percent" in class_name:
                    # Two Rate, Three Color
                    if "conform-set-dscp-transmit" in class_name["police-cir-percent"]["police"]["cir"]["percent"]["actions"] and ("exceed-set-dscp-transmit" in class_name[
                        "police-cir-percent"]["police"]["cir"]["percent"]["actions"] or "exceed-drop" in class_name["police-cir-percent"]["police"]["cir"]["percent"]["actions"]) and (
                            "violate-set-dscp-transmit" in class_name["police-cir-percent"]["police"][
                            "cir"]["percent"]["actions"] or "violate-drop" in class_name["police-cir-percent"]["police"]["cir"]["percent"]["actions"]):
                        set_sched_policy_three_color_percent(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler)
                    # One Rate, Two Color
                    elif "conform-set-dscp-transmit" in class_name["police-cir-percent"]["police"]["cir"]["percent"]["actions"] and ("exceed-set-dscp-transmit" in class_name[
                        "police-cir-percent"]["police"]["cir"]["percent"]["actions"] or "exceed-drop" in class_name["police-cir-percent"]["police"]["cir"]["percent"]["actions"]):
                        set_sched_policy_two_color_percent(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler)
                    intf_to_scheduler_map(config_leftover, policy_map, intf_to_sched_list, openconfig_scheduler)

    for class_map_index, class_map in enumerate(class_map_list):
        # Set QoS class-maps
        if "ip" in class_map["match"]:
            # class-map with 'match ip'
            set_qos_class_map_ip(config_leftover, class_map_index, class_map, openconfig_class_map, policy_map_list)
        else:
            set_qos_class_map(config_leftover, class_map_index, class_map, openconfig_class_map, policy_map_list)
            
    for interface in interface_dict:
        if interface:
            # Map OC interface and scheduler
            set_qos_interface(config_leftover, openconfig_interface, interface, interface_dict[interface], intf_to_sched_list, openconfig_scheduler)


def intf_to_scheduler_map(config_leftover, policy_map, intf_to_sched_list, openconfig_scheduler):

    # Map policy-map and scheduler
    intf_to_sched_list.append({policy_map["name"]: openconfig_scheduler[-1]['openconfig-qos:name']})
    return intf_to_sched_list


def set_qos_class_default(cd_index, policy_map, openconfig_class_map):

    openconfig_class_map.append({
        "openconfig-qos:name": "class-default",
        "openconfig-qos:config": {"openconfig-qos:name:": "class-default"},
        "openconfig-qos:terms": {"openconfig-qos:term": [{"openconfig-qos:id": "term-default-" + f'{cd_index}',
                                                        "openconfig-qos:config": {
                                                            "openconfig-qos:id": "term-default-" + f'{cd_index}'
                                                        },
                                                        "openconfig-qos:actions": {
                                                            "openconfig-qos:config": {
                                                                "openconfig-qos:target-group": policy_map["name"]
                                                            }
                                                        }
                                                        }
                                                        ]
                                }
                                })


def set_qos_policy_map(policy_map, openconfig_policy_map):

    openconfig_policy_map.append({"openconfig-qos:name": policy_map["name"],
                                 "openconfig-qos:config": {
                                     "openconfig-qos:name": policy_map["name"]
                                 }})


def set_sched_class_default_priority_percent(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler):

    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default",
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default"
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:priority": "STRICT",
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir-pct": policy_map["class-default"]["class"][0]["priority"]["percent"],
                        "openconfig-qos:queuing-behavior": "SHAPE"
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class-default"] = None
    

def set_sched_class_default_priority_bits(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler):

    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default",
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default"
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:priority": "STRICT",
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir": policy_map["class-default"]["class"][0]["priority"]["kilo-bits"],
                        "openconfig-qos:bc": policy_map["class-default"]["class"][0]["priority"]["burst"],
                        "openconfig-qos:queuing-behavior": "SHAPE"
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class-default"] = None


def set_sched_class_default_bandwidth_percent(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler):

    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default",
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default"
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir-pct": policy_map["class-default"]["class"][0]["bandwidth"]["percent"],
                        "openconfig-qos:queuing-behavior": "SHAPE"
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class-default"] = None


def set_sched_class_default_bandwidth_bits(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler):

    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default",
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default"
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir": policy_map["class-default"]["class"][0]["bandwidth"]["bits"],
                        "openconfig-qos:queuing-behavior": "SHAPE"
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class-default"] = None


def set_sched_class_default_policy_three_color(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler):

    cd_new_police = policy_map["class-default"]["class"][0]["police-policy-map"]["police"]
    cd_new_actions = cd_new_police["actions"]
    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default",
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default"
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:type": "TWO_RATE_THREE_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:two-rate-three-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir": set_class_default_qos_cir(cd_new_police),
                        "openconfig-qos:bc": set_class_default_qos_bc(cd_new_police),
                        "openconfig-qos:pir": set_class_default_qos_pir(cd_new_police),
                        "openconfig-qos:be": set_class_default_qos_be(cd_new_police)
                    },
                    "openconfig-qos:conform-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_class_default_policy_conform(cd_new_actions)
                        }
                    },
                    "openconfig-qos:exceed-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_class_default_policy_exceed(cd_new_actions)[0],
                            "openconfig-qos:drop": set_class_default_policy_exceed(cd_new_actions)[1]
                        }
                    },
                    "openconfig-qos:violate-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_class_default_policy_violate(cd_new_actions)[0],
                            "openconfig-qos:drop": set_class_default_policy_violate(cd_new_actions)[1]
                        }
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class-default"] = None


def set_sched_class_default_policy_two_color(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler):

    cd_new_police = policy_map["class-default"]["class"][0]["police-policy-map"]["police"]
    cd_new_actions = cd_new_police["actions"]
    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default",
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default"
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir": set_class_default_qos_cir(cd_new_police),
                        "openconfig-qos:bc": set_class_default_qos_bc(cd_new_police),
                        "openconfig-qos:queuing-behavior": 'POLICE'
                    },
                    "openconfig-qos:conform-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_class_default_policy_conform(cd_new_actions)
                        }
                    },
                    "openconfig-qos:exceed-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_class_default_policy_exceed(cd_new_actions)[0],
                            "openconfig-qos:drop": set_class_default_policy_exceed(cd_new_actions)[1]
                        }
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class-default"] = None


def set_sched_class_default_policy_three_color_percent(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler):

    cd_new_percent = policy_map["class-default"]["class"][0]["police-cir-percent"]["police"]["cir"]["percent"]
    cd_new_percent_actions = cd_new_percent["actions"]
    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default",
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default"
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:type": "TWO_RATE_THREE_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:two-rate-three-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir-pct": set_class_default_qos_cir_percent(cd_new_percent),
                        "openconfig-qos:bc": set_class_default_qos_bc_percent(cd_new_percent),
                        "openconfig-qos:pir-pct": set_class_default_qos_pir_percent(cd_new_percent),
                        "openconfig-qos:be": set_class_default_qos_be_percent(cd_new_percent)
                    },
                    "openconfig-qos:conform-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_class_default_policy_conform_percent(cd_new_percent_actions)
                        }
                    },
                    "openconfig-qos:exceed-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_class_default_policy_exceed_percent(cd_new_percent_actions)[0],
                            "openconfig-qos:drop": set_class_default_policy_exceed_percent(cd_new_percent_actions)[1]
                        }
                    },
                    "openconfig-qos:violate-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_class_default_policy_violate_percent(cd_new_percent_actions)[0],
                            "openconfig-qos:drop": set_class_default_policy_violate_percent(cd_new_percent_actions)[1]
                        }
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class-default"] = None


def set_sched_class_default_policy_two_color_percent(config_leftover, cd_index, policy_map_index, policy_map, openconfig_scheduler):

    cd_new_percent = policy_map["class-default"]["class"][0]["police-cir-percent"]["police"]["cir"]["percent"]
    cd_new_percent_actions = cd_new_percent["actions"]
    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default",
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{cd_index}-'"class-default"
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:priority": "STRICT",
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir-pct": set_class_default_qos_cir_percent(cd_new_percent),
                        "openconfig-qos:bc": set_class_default_qos_bc_percent(cd_new_percent),
                        "openconfig-qos:queuing-behavior": 'POLICE'
                    },
                    "openconfig-qos:conform-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_class_default_policy_conform_percent(cd_new_percent_actions)
                        }
                    },
                    "openconfig-qos:exceed-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_class_default_policy_exceed_percent(cd_new_percent_actions)[0],
                            "openconfig-qos:drop": set_class_default_policy_exceed_percent(cd_new_percent_actions)[1]
                        }
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class-default"] = None


def set_sched_priority_percent(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler):

    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}',
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}'
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:priority": "STRICT",
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir-pct": class_name["priority"]["percent"],
                        "openconfig-qos:queuing-behavior": "SHAPE"
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class"][class_index] = None


def set_sched_priority_bits(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler):

    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}',
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}'
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:priority": "STRICT",
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir": class_name["priority"]["kilo-bits"],
                        "openconfig-qos:bc": class_name["priority"]["burst"],
                        "openconfig-qos:queuing-behavior": "SHAPE"
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class"][class_index] = None


def set_sched_bandwidth_percent(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler):

    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}',
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}'
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir-pct": class_name["bandwidth"]["percent"],
                        "openconfig-qos:queuing-behavior": "SHAPE"
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class"][class_index] = None


def set_sched_bandwidth_bits(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler):

    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}',
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}'
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir": class_name["bandwidth"]["bits"],
                        "openconfig-qos:queuing-behavior": "SHAPE"
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class"][class_index] = None


def set_sched_policy_three_color(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler):

    cm_new_police = class_name["police-policy-map"]["police"]
    cm_new_actions = cm_new_police["actions"]
    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}',
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}'
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:type": "TWO_RATE_THREE_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:two-rate-three-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir": set_qos_cir(cm_new_police),
                        "openconfig-qos:bc": set_qos_bc(cm_new_police),
                        "openconfig-qos:pir": set_qos_pir(cm_new_police),
                        "openconfig-qos:be": set_qos_be(cm_new_police)
                    },
                    "openconfig-qos:conform-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_policy_conform(cm_new_actions)
                        }
                    },
                    "openconfig-qos:exceed-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_policy_exceed(cm_new_actions)[0],
                            "openconfig-qos:drop": set_policy_exceed(cm_new_actions)[1]
                        }
                    },
                    "openconfig-qos:violate-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_policy_violate(cm_new_actions)[0],
                            "openconfig-qos:drop": set_policy_violate(cm_new_actions)[1]
                        }
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class"][class_index] = None


def set_sched_policy_two_color(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler):

    cm_new_police = class_name["police-policy-map"]["police"]
    cm_new_actions = cm_new_police["actions"]
    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}',
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}'
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir": set_qos_cir(cm_new_police),
                        "openconfig-qos:bc": set_qos_bc(cm_new_police),
                        "openconfig-qos:queuing-behavior": "POLICE"
                    },
                    "openconfig-qos:conform-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_policy_conform(cm_new_actions)
                        }
                    },
                    "openconfig-qos:exceed-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_policy_exceed(cm_new_actions)[0],
                            "openconfig-qos:drop": set_policy_exceed(cm_new_actions)[1]
                        }
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class"][class_index] = None


def set_sched_policy_three_color_percent(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler):

    cm_new_percent = class_name["police-cir-percent"]["police"]["cir"]["percent"]
    cm_new_percent_actions = cm_new_percent["actions"]
    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}',
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}'
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:type": "TWO_RATE_THREE_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:two-rate-three-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir": set_qos_cir_percent(cm_new_percent),
                        "openconfig-qos:bc": set_qos_bc_percent(cm_new_percent),
                        "openconfig-qos:pir": set_qos_pir_percent(cm_new_percent),
                        "openconfig-qos:be": set_qos_be_percent(cm_new_percent)
                    },
                    "openconfig-qos:conform-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_policy_conform_percent(cm_new_percent_actions)
                        }
                    },
                    "openconfig-qos:exceed-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_policy_exceed_percent(cm_new_percent_actions)[0],
                            "openconfig-qos:drop": set_policy_exceed_percent(cm_new_percent_actions)[1]
                        }
                    },
                    "openconfig-qos:violate-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_policy_violate_percent(cm_new_percent_actions)[0],
                            "openconfig-qos:drop": set_policy_violate_percent(cm_new_percent_actions)[1]
                        }
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class"][class_index] = None


def set_sched_policy_two_color_percent(config_leftover, class_index, policy_map_index, class_name, c_index, policy_map, openconfig_scheduler):

    cm_new_percent = class_name["police-cir-percent"]["police"]["cir"]["percent"]
    cm_new_percent_actions = cm_new_percent["actions"]
    openconfig_scheduler.append({
        "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}',
        "openconfig-qos:config": {
            "openconfig-qos:name": "sched-"f'{c_index}-'f'{class_name["name"]}'
        },
        "openconfig-qos:schedulers": {
            "openconfig-qos:scheduler": [{
                "openconfig-qos:sequence": 10,
                "openconfig-qos:config": {
                    "openconfig-qos:sequence": 10,
                    "openconfig-qos:type": "ONE_RATE_TWO_COLOR"
                },
                "openconfig-qos:output": {
                    "openconfig-qos:config": {
                        "openconfig-qos:output-type": "FWD_GROUP",
                        "openconfig-qos:output-fwd-group": policy_map["name"]
                    }
                },
                "openconfig-qos:one-rate-two-color": {
                    "openconfig-qos:config": {
                        "openconfig-qos:cir-pct": set_qos_cir_percent(cm_new_percent),
                        "openconfig-qos:bc": set_qos_bc_percent(cm_new_percent),
                        "openconfig-qos:queuing-behavior": "POLICE"
                    },
                    "openconfig-qos:conform-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_policy_conform_percent(cm_new_percent_actions)
                        }
                    },
                    "openconfig-qos:exceed-action": {
                        "openconfig-qos:config": {
                            "openconfig-qos:set-dscp": set_policy_exceed_percent(cm_new_percent_actions)[0],
                            "openconfig-qos:drop": set_policy_exceed_percent(cm_new_percent_actions)[1]
                        }
                    }
                }
            }]
        }
    })

    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["name"] = None
    config_leftover["tailf-ned-cisco-ios:policy-map"][policy_map_index]["class"][class_index] = None


def set_class_default_qos_cir(cd_new_police):

    cir = None
    if "cir" in cd_new_police:
        cir = cd_new_police["cir"]
    
    return cir


def set_class_default_qos_bc(cd_new_police):

    bc = None
    if "bc" in cd_new_police:
        bc = cd_new_police["bc"]
    
    return bc


def set_class_default_qos_pir(cd_new_police):

    pir = None
    if "pir" in cd_new_police:
        pir = cd_new_police["pir"]
    
    return pir


def set_class_default_qos_be(cd_new_police):

    be = None
    if "pir-be" in cd_new_police and "be" in cd_new_police["pir-be"]:
        be = cd_new_police["pir-be"]["be"]
    
    return be


def set_class_default_qos_cir_percent(cd_new_percent):

    cir_percent = None
    if "percentage" in cd_new_percent:
        cir_percent = cd_new_percent["percentage"]
    
    return cir_percent


def set_class_default_qos_bc_percent(cd_new_percent):

    bc_percent = None
    if "bc" in cd_new_percent:
        bc_percent = cd_new_percent["bc"]
    
    return bc_percent


def set_class_default_qos_pir_percent(cd_new_percent):

    pir_percent = None
    if "pir" in cd_new_percent and "percent" in cd_new_percent["pir"]:
        pir_percent = cd_new_percent["pir"]["percent"]
    
    return pir_percent


def set_class_default_qos_be_percent(cd_new_percent):

    be_percent = None
    if "pir-be" in cd_new_percent and "be" in cd_new_percent["pir-be"]:
        be_percent = cd_new_percent["pir-be"]["be"]
    
    return be_percent


def set_qos_cir(cm_new_police):

    cir = None
    if "cir" in cm_new_police:
        cir = cm_new_police["cir"]
    
    return cir

def set_qos_bc(cm_new_police):

    bc = None
    if "bc" in cm_new_police:
        bc = cm_new_police["bc"]
    
    return bc

def set_qos_pir(cm_new_police):

    pir = None
    if "pir" in cm_new_police:
        pir = cm_new_police["pir"]
    
    return pir

def set_qos_be(cm_new_police):

    be = None
    if "pir-be" in cm_new_police and "be" in cm_new_police["pir-be"]:
        be = cm_new_police["pir-be"]["be"]
    
    return be


def set_qos_cir_percent(cm_new_percent):

    cir_percent = None
    if "percentage" in cm_new_percent:
        cir_percent = cm_new_percent["percentage"]
    
    return cir_percent


def set_qos_bc_percent(cm_new_percent):

    bc_percent = None
    if "bc" in cm_new_percent:
        bc_percent = cm_new_percent["bc"]
    
    return bc_percent


def set_qos_pir_percent(cm_new_percent):

    pir_percent = None
    if "pir" in cm_new_percent and "percent" in cm_new_percent["pir"]:
        pir_percent = cm_new_percent["pir"]["percent"]
    
    return pir_percent


def set_qos_be_percent(cm_new_percent):

    be_percent = None
    if "pir-be" in cm_new_percent and "be" in cm_new_percent["pir-be"]:
        be_percent = cm_new_percent["pir-be"]["be"]
    
    return be_percent


def set_class_default_policy_conform(cd_new_actions):

    conform = None
    if "set-dscp-transmit" in cd_new_actions["conform-set-dscp-transmit"]["conform-action"]:
        conform = cd_new_actions["conform-set-dscp-transmit"]["conform-action"]["set-dscp-transmit"]
    
    if type(conform) is str:
        conform = dscp_dict.get(conform, 'default')

    return conform


def set_class_default_policy_exceed(cd_new_actions):

    exceed = drop = None
    if "exceed-set-dscp-transmit" in cd_new_actions:
        exceed = cd_new_actions["exceed-set-dscp-transmit"]["exceed-action"]["set-dscp-transmit"]
    elif "exceed-drop" in cd_new_actions:
        drop = True
    
    if type(exceed) is str:
        exceed = dscp_dict.get(exceed, 'default')

    return exceed, drop


def set_class_default_policy_violate(cd_new_actions):

    violate = drop = None
    if "violate-set-dscp-transmit" in cd_new_actions:
        violate = cd_new_actions["violate-set-dscp-transmit"]["violate-action"]["set-dscp-transmit"]
    elif "violate-drop" in cd_new_actions:
        drop = True

    if type(violate) is str:
        violate = dscp_dict.get(violate, 'default')

    return violate, drop


def set_class_default_policy_conform_percent(cd_new_percent_actions):

    conform_percent = None
    if "set-dscp-transmit" in cd_new_percent_actions["conform-set-dscp-transmit"]["conform-action"]:
        conform_percent = cd_new_percent_actions["conform-set-dscp-transmit"]["conform-action"]["set-dscp-transmit"]

    if type(conform_percent) is str:
        conform_percent = dscp_dict.get(conform_percent, 'default')

    return conform_percent


def set_class_default_policy_exceed_percent(cd_new_percent_actions):

    exceed_percent = drop = None
    if "exceed-set-dscp-transmit" in cd_new_percent_actions:
        exceed_percent = cd_new_percent_actions["exceed-set-dscp-transmit"]["exceed-action"]["set-dscp-transmit"]
    elif "exceed-drop" in cd_new_percent_actions:
        drop = True
    
    if type(exceed_percent) is str:
        exceed_percent = dscp_dict.get(exceed_percent, 'default')

    return exceed_percent, drop


def set_class_default_policy_violate_percent(cd_new_percent_actions):

    violate_percent = drop = None
    if "violate-set-dscp-transmit" in cd_new_percent_actions:
        violate_percent = cd_new_percent_actions["violate-set-dscp-transmit"]["violate-action"]["set-dscp-transmit"]
    elif "violate-drop" in cd_new_percent_actions:
        drop = True

    if type(violate_percent) is str:
        violate_percent = dscp_dict.get(violate_percent, 'default')

    return violate_percent, drop


def set_policy_conform(cm_new_actions):

    conform = None
    if "set-dscp-transmit" in cm_new_actions["conform-set-dscp-transmit"]["conform-action"]:
        conform = cm_new_actions["conform-set-dscp-transmit"]["conform-action"]["set-dscp-transmit"]
    
    if type(conform) is str:
        conform = dscp_dict.get(conform, 'default')

    return conform

def set_policy_exceed(cm_new_actions):

    exceed = drop = None
    if "exceed-set-dscp-transmit" in cm_new_actions:
        exceed = cm_new_actions["exceed-set-dscp-transmit"]["exceed-action"]["set-dscp-transmit"]
    elif "exceed-drop" in cm_new_actions:
        drop = True
    
    if type(exceed) is str:
        exceed = dscp_dict.get(exceed, 'default')

    return exceed, drop


def set_policy_violate(cm_new_actions):

    violate = drop = None
    if "violate-set-dscp-transmit" in cm_new_actions:
        violate = cm_new_actions["violate-set-dscp-transmit"]["violate-action"]["set-dscp-transmit"]
    elif "violate-drop" in cm_new_actions:
        drop = True

    if type(violate) is str:
        violate = dscp_dict.get(violate, 'default')

    return violate, drop


def set_policy_conform_percent(cm_new_percent_actions):

    conform_percent = None
    if "set-dscp-transmit" in cm_new_percent_actions["conform-set-dscp-transmit"]["conform-action"]:
        conform_percent = cm_new_percent_actions["conform-set-dscp-transmit"]["conform-action"]["set-dscp-transmit"]

    if type(conform_percent) is str:
        conform_percent = dscp_dict.get(conform_percent, 'default')

    return conform_percent


def set_policy_exceed_percent(cm_new_percent_actions):

    exceed_percent = drop = None
    if "exceed-set-dscp-transmit" in cm_new_percent_actions:
        exceed_percent = cm_new_percent_actions["exceed-set-dscp-transmit"]["exceed-action"]["set-dscp-transmit"]
    elif "exceed-drop" in cm_new_percent_actions:
        drop = True

    if type(exceed_percent) is str:
        exceed_percent = dscp_dict.get(exceed_percent, 'default')

    return exceed_percent, drop


def set_policy_violate_percent(cm_new_percent_actions):

    violate_percent = drop = None
    if "violate-set-dscp-transmit" in cm_new_percent_actions:
        violate_percent = cm_new_percent_actions["violate-set-dscp-transmit"]["violate-action"]["set-dscp-transmit"]
    elif "violate-drop" in cm_new_percent_actions:
        drop = True

    if type(violate_percent) is str:
        violate_percent = dscp_dict.get(violate_percent, 'default')

    return violate_percent, drop


def set_qos_interface(config_leftover, openconfig_interface, interface, interface_list, intf_to_sched_list, openconfig_scheduler):

    for index, intf in enumerate(interface_list):
        openconfig_interface.append({
            "openconfig-qos:interface-id": interface + str(intf.get("name")),
            "openconfig-qos:config": {
                "openconfig-qos:interface-id": interface + str(intf.get("name"))
            },
            "openconfig-qos:input": {
                "openconfig-qos:scheduler-policy": {
                    "openconfig-qos:config": {
                        "openconfig-qos:name": set_scheduler_policy_input(
                            config_leftover, openconfig_scheduler, interface, intf, intf_to_sched_list, index)
                    }
                }
            },
            "openconfig-qos:output": {
                "openconfig-qos:scheduler-policy": {
                    "openconfig-qos:config": {
                        "openconfig-qos:name": set_scheduler_policy_output(
                            config_leftover, openconfig_scheduler, interface, intf, intf_to_sched_list, index)
                    }
                }
            }
        })


def set_scheduler_policy_output(config_leftover, openconfig_scheduler, interface, intf, intf_to_sched_list, index):

    scheduler_out = None
    if "service-policy" in intf:
        for int_index in intf_to_sched_list:
            if "output" in intf["service-policy"] and intf["service-policy"]["output"] in int_index:
                scheduler_out = int_index[intf['service-policy']['output']]
                config_leftover["tailf-ned-cisco-ios:interface"][interface][index]["service-policy"]["output"] = None
    
    return scheduler_out


def set_scheduler_policy_input(config_leftover, openconfig_scheduler, interface, intf, intf_to_sched_list, index):

    scheduler_in = None
    if "service-policy" in intf:
        for intf_to_sched in intf_to_sched_list:
            if "input" in intf["service-policy"] and intf["service-policy"]["input"] in intf_to_sched:
                scheduler_in = intf_to_sched[intf['service-policy']['input']]
                config_leftover["tailf-ned-cisco-ios:interface"][interface][index]["service-policy"]["input"] = None
    
    return scheduler_in


def set_qos_class_map_ip(config_leftover, class_map_index, class_map, openconfig_class_map, policy_map_list):

    if len(class_map["match"]["ip"]["dscp"]) == 1:
        openconfig_class_map.append({
            "openconfig-qos:name": class_map["name"],
            "openconfig-qos:config": {"openconfig-qos:name:": class_map["name"],
                                    "openconfig-qos:type:": "IPV4"},
            "openconfig-qos:terms": {"openconfig-qos:term": [{"openconfig-qos:id": "term-" + f'{class_map_index + 1}',
                                                            "openconfig-qos:config": {
                                                                "openconfig-qos:id": "term-" + f'{class_map_index + 1}'
                                                            },
                                                            "openconfig-qos:conditions": {
                                                                "openconfig-qos:ipv4": {
                                                                    "openconfig-qos:config": {
                                                                        "openconfig-qos:dscp": modify_dscp(class_map["match"]["ip"]["dscp"]),
                                                                        "openconfig-qos:protocol": 4
                                                                    }
                                                                }
                                                            },
                                                            "openconfig-qos:actions": {
                                                                "openconfig-qos:config": {
                                                                      "openconfig-qos:target-group": get_policy_map_group(class_map_index, class_map, policy_map_list)
                                                                }
                                                            }
                                                            }
                                                            ]
                                    }
                                    })
        config_leftover["tailf-ned-cisco-ios:class-map"][class_map_index] = None
    elif len(class_map["match"]["ip"]["dscp"]) > 1:
        openconfig_class_map.append({
            "openconfig-qos:name": class_map["name"],
            "openconfig-qos:config": {"openconfig-qos:name:": class_map["name"],
                                    "openconfig-qos:type:": "IPV4"},
            "openconfig-qos:terms": {"openconfig-qos:term": [{"openconfig-qos:id": "term-" + f'{class_map_index + 1}',
                                                            "openconfig-qos:config": {
                                                                "openconfig-qos:id": "term-" + f'{class_map_index + 1}'
                                                            },
                                                            "openconfig-qos:conditions": {
                                                                "openconfig-qos:ipv4": {
                                                                    "openconfig-qos:config": {
                                                                        "openconfig-qos:dscp-set": modify_dscp_list(class_map["match"]["ip"]["dscp"]),
                                                                        "openconfig-qos:protocol": 4
                                                                    }
                                                                }
                                                            },
                                                            "openconfig-qos:actions": {
                                                                "openconfig-qos:config": {
                                                                      "openconfig-qos:target-group": get_policy_map_group(class_map_index, class_map, policy_map_list)
                                                                }
                                                            }
                                                            }
                                                            ]
                                    }
                                    })
        config_leftover["tailf-ned-cisco-ios:class-map"][class_map_index] = None


def set_qos_class_map(config_leftover, class_map_index, class_map, openconfig_class_map, policy_map_list):

    if len(class_map["match"]["dscp"]) == 1:
        openconfig_class_map.append({
            "openconfig-qos:name": class_map["name"],
            "openconfig-qos:config": {"openconfig-qos:name:": class_map["name"]
                                    },
            "openconfig-qos:terms": {"openconfig-qos:term": [{"openconfig-qos:id": "term-" + f'{class_map_index + 1}',
                                                            "openconfig-qos:config": {
                                                                "openconfig-qos:id": "term-" + f'{class_map_index + 1}'
                                                            },
                                                            "openconfig-qos:conditions": {
                                                                "openconfig-qos:ipv4": {
                                                                    "openconfig-qos:config": {
                                                                        "openconfig-qos:dscp": modify_dscp(class_map["match"]["dscp"])
                                                                    }
                                                                }
                                                            },
                                                            "openconfig-qos:actions": {
                                                                "openconfig-qos:config": {
                                                                      "openconfig-qos:target-group": get_policy_map_group(class_map_index, class_map, policy_map_list)
                                                                }
                                                            }
                                                            }
                                                            ]
                                    }
                                    })
        config_leftover["tailf-ned-cisco-ios:class-map"][class_map_index] = None
    elif len(class_map["match"]["dscp"]) > 1:
        openconfig_class_map.append({
        "openconfig-qos:name": class_map["name"],
        "openconfig-qos:config": {"openconfig-qos:name:": class_map["name"]
                                  },
        "openconfig-qos:terms": {"openconfig-qos:term": [{"openconfig-qos:id": "term-" + f'{class_map_index + 1}',
                                                          "openconfig-qos:config": {
                                                              "openconfig-qos:id": "term-" + f'{class_map_index + 1}'
                                                          },
                                                          "openconfig-qos:conditions": {
                                                              "openconfig-qos:ipv4": {
                                                                  "openconfig-qos:config": {
                                                                      "openconfig-qos:dscp-set": modify_dscp_list(class_map["match"]["dscp"])
                                                                  }
                                                              }
                                                          },
                                                          "openconfig-qos:actions": {
                                                              "openconfig-qos:config": {
                                                                  "openconfig-qos:target-group": get_policy_map_group(class_map_index, class_map, policy_map_list)
                                                              }
                                                          }
                                                          }
                                                        ]
                                }
                                })
        config_leftover["tailf-ned-cisco-ios:class-map"][class_map_index] = None


def modify_dscp(dscp_list):
    dscp = dscp_list[0]
    if type(dscp) is int and (dscp % 2) != 0:
        return dscp
    return dscp_dict.get(dscp, 'default')


def modify_dscp_list(dscp_list):
    new_dscp_list = []
    for dscp in dscp_list:
        if type(dscp) is int and (dscp % 2) != 0:
            new_dscp_list.append(dscp)
        else:
            new_dscp_list.append(dscp_dict.get(dscp, 'default'))
    
    return new_dscp_list


def get_policy_map_group(class_map_index, class_map, policy_map_list):
    
    policy = None
    for policy_map in policy_map_list:
        if "class-default" not in policy_map:
            for pol in policy_map["class"]:
                if pol["name"] == class_map["name"]:
                    policy = policy_map["name"]
    return policy


def main(before: dict, leftover: dict, translation_notes: list = []) -> dict:
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
    :return: MDD Openconfig Network Instances configuration: dict
    """

    configure_xe_qos(before, leftover)
    translation_notes += qos_notes

    return openconfig_qos


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
    main(config_before_dict, config_leftover_dict)
    config_name = "_qos"
    config_remaining_name = "_remaining_qos"
    oc_name = "_openconfig_qos"
    common.print_and_test_configs(
        "xe1", config_before_dict, config_leftover_dict, openconfig_qos,
        config_name, config_remaining_name, oc_name, qos_notes)
else:
    # This is needed for now due to top level __init__.py. We need to determine if contents in __init__.py is still necessary.
    if (find_spec("package_nso_to_oc") is not None):
        from package_nso_to_oc.xe import common_xe
        from package_nso_to_oc import common
    else:
        from xe import common_xe
        import common