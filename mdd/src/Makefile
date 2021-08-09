all: fxs
.PHONY: all

# Include standard NCS examples build definitions and rules
include $(NCS_DIR)/src/ncs/build/include.ncs.mk

OC_MODELS = $(filter-out %aaa-tacacs.yang %aaa-radius.yang %grpc.yang, $(wildcard yang/openconfig/system/*.yang)) \
			yang/openconfig/platform/openconfig-platform.yang yang/openconfig/platform/openconfig-platform-types.yang \
			yang/openconfig/openconfig-extensions.yang \
			$(wildcard yang/openconfig/types/*.yang) \
			$(filter-out %openconfig-qos-interfaces.yang %openconfig-qos-elements.yang, $(wildcard yang/openconfig/qos/*.yang)) \
			$(filter-out %openconfig-rib-bgp-tables.yang %openconfig-rib-bgp-shared-attributes.yang %openconfig-rib-bgp-attributes.yang %openconfig-rib-bgp-table-attributes.yang, $(wildcard yang/openconfig/rib/*.yang)) \
			$(filter-out %openconfig-network-instance-l2.yang, $(wildcard yang/openconfig/network-instance/*.yang)) \
			$(wildcard yang/openconfig/policy/*.yang) \
      $(wildcard yang/openconfig/bfd/*.yang) \
			$(wildcard yang/openconfig/stp/*.yang) \
			$(wildcard yang/openconfig/local-routing/*.yang) \
			$(filter-out %openconfig-mpls-te.yang %openconfig-mpls-igp.yang %openconfig-mpls-static.yang, $(wildcard yang/openconfig/mpls/*.yang)) \
			$(filter-out %openconfig-ospfv2-global.yang %openconfig-ospfv2-area.yang %openconfig-ospfv2-area-interface.yang %openconfig-ospfv2-lsdb.yang %openconfig-ospfv2-common.yang, $(wildcard yang/openconfig/ospf/*.yang)) \
			$(filter-out %openconfig-pf-forwarding-policies.yang %openconfig-pf-path-groups.yang %openconfig-pf-interfaces.yang, $(wildcard yang/openconfig/policy-forwarding/*.yang)) \
			$(wildcard yang/openconfig/segment-routing/*.yang) \
			$(filter-out %openconfig-isis-lsp.yang %openconfig-isis-routing.yang, $(wildcard yang/openconfig/isis/*.yang)) \
			$(filter-out %openconfig-aft-ipv4.yang %openconfig-aft-ipv6.yang %openconfig-aft-mpls.yang %openconfig-aft-pf.yang %openconfig-aft-ethernet.yang %openconfig-aft-common.yang, $(wildcard yang/openconfig/aft/*.yang)) \
			$(wildcard yang/openconfig/multicast/*.yang) \
			$(wildcard yang/openconfig/acl/*.yang) \
			$(wildcard yang/openconfig/lacp/*.yang) \
			$(wildcard yang/openconfig/lldp/*.yang) \
			$(wildcard yang/openconfig/macsec/*.yang) \
			$(filter-out %openconfig-bgp-common.yang %openconfig-bgp-common-multiprotocol.yang %openconfig-bgp-common-structure.yang %openconfig-bgp-peer-group.yang %openconfig-bgp-neighbor.yang %openconfig-bgp-global.yang %openconfig-bgp-errors.yang, $(wildcard yang/openconfig/bgp/*.yang)) \
			$(filter-out %if-8021X.yang %if-ethernet-ext.yang %if-ip-ext.yang %if-sdn-ext.yang %if-tunnel.yang, $(wildcard yang/openconfig/interfaces/*.yang)) \
			$(wildcard yang/openconfig/vlan/*.yang) \
			$(wildcard yang/extensions/*.yang)
IETF_MODELS = $(wildcard yang/ietf/*.yang)

SRC = yang/mdd.yang $(OC_MODELS) $(IETF_MODELS)
SRC_FILES = $(notdir $(SRC))
SRC_DIRS = $(sort $(dir $(SRC)))
DIRS = ../load-dir java/src/$(JDIR)/$(NS)
FXS = $(SRC_FILES:%.yang=../load-dir/%.fxs)

vpath %.yang $(SRC_DIRS)

YANGPATH += $(SRC_DIRS)

NCSCPATH   = $(YANGPATH:%=--yangpath %)
YANGERPATH = $(YANGPATH:%=--path %)

fxs: $(DIRS) $(FXS)

$(DIRS):
	mkdir -p $@

../load-dir/%.fxs: %.yang
	$(NCSC)  `ls $*-ann.yang  > /dev/null 2>&1 && echo "-a $*-ann.yang"` \
		--fail-on-warnings \
		$(NCSCPATH) \
		-c -o $@ $<

clean:
	rm -rf $(DIRS)
.PHONY: clean

dumpvars:
	@$(foreach V,$(sort $(.VARIABLES)),           \
	$(if $(filter-out environ% default automatic,$(origin $V)),$(info $V=$($V) ($(value $V)))))
.PHONY: dumpvars
