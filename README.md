# nso-oc-services
NSO OpenConfig Services

<img src="https://github.com/model-driven-devops/nso-oc-services/raw/main/oc-nso.png" width="400">


The NSO OpenConfig Services package is a set of services that implement the OpenConfig
YANG models in NSO.  The goal is to provide an open, standard, model-driven API for
any device using OpenConfig.

The initial set of OpenConfig models to be implement are intended to provide covererage for
80% of most network's use cases and include:
- openconfig-system
- openconfig-interfaces
- openconfig-vlan
- openconfig-local-routing
- openconfig-bgp
- openconfig-ospf
- openconfig-qos
- openconfig-lacp
- openconfig-lldp
- openconfig-acl
- openconfig-stp
- openconfig-multicast
- openconfig-network-instance

The first platforms to be included are:
- Cisco IOS-XE
- Cisco IOS-XR
- Cisco NXOS
