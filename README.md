# NSO OpenConfig Services

## Overview

<img src="https://github.com/model-driven-devops/nso-oc-services/raw/main/oc-nso.png" width="400">


The NSO OpenConfig Services package is a set of services that implement the OpenConfig
YANG models in NSO.  The goal is to provide an open, standard, model-driven API for
any device using OpenConfig to make network automation easier and more uniform.

This uniform API comes from two places.  First, the [OpenConfig](https://www.openconfig.net/)
YANG models provide a
"consistent set of vendor-neutral data models (written in YANG) based on actual operational
needs from use cases and requirements from multiple network operators." (https://www.openconfig.net/).

Second,
[Cisco Network Services Orchestrator](https://www.cisco.com/c/en/us/products/cloud-systems-management/network-services-orchestrator/index.html)
(NSO) provides a consistent set of capabilities across all platforms such as:
- Rollback
- Transactional changes
- Min-diff changes over the wire
- High-scalable architecture.

Additionally, NSO's Network Element Drivers (NED) communicate over the native protocol supported by
the device making it possible to support nearly any device from any vendor.

The initial set of OpenConfig models to be implement are intended to provide coverage for
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
