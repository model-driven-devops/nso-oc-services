# -*- mode: python; python-indent: 4 -*-
from re import compile

from _ncs import TransCtxRef
from ncs.maagic import Root, ListElement
from ncs.application import Application, Service

from translation.openconfig_xe.xe_main import check_xe_features
from translation.openconfig_xe.xe_main import clean_xe_cdb
from translation.openconfig_xr.xr_main import check_xr_features
from translation.openconfig_xr.xr_main import clean_xr_cdb
from translation.openconfig_nx.nx_main import check_nx_features

from translation.common import NsoProps

regex_device = compile(r'device{(.*)}\/')

class OCCallback(Service):
    @Service.create
    def cb_create(self, tctx: TransCtxRef, root: Root, service: ListElement, proplist: list):
        self.log.info(f'Service create(service={service._path})')
        # Get device name from service path
        r = regex_device.search(service._path)
        nso_props = NsoProps(service, root, proplist, r.group(1)) 

        # Each NED may have a template and will have python processing code
        if 'cisco-ios-cli' in nso_props.root.devices.device[nso_props.device_name].device_type.cli.ned_id:
            clean_xe_cdb(nso_props)
            check_xe_features(self, nso_props)
        elif 'cisco-iosxr-cli' in nso_props.root.devices.device[nso_props.device_name].device_type.cli.ned_id:
            clean_xr_cdb(nso_props)
            check_xr_features(self, nso_props)
        elif 'cisco-nx-cli' in nso_props.root.devices.device[nso_props.device_name].device_type.cli.ned_id:
            check_nx_features(self, nso_props)


def update_vars(initial_vars: dict, proplist: list) -> dict:
    """
    Updates initial vars with transformed vars
    :param initial_vars: dictionary of template variables
    :param proplist: list of tuples containing template variable to value
    :return: dictionary of template variable names to values
    """
    if proplist:
        for var_tuple in proplist:
            if var_tuple[0] in initial_vars:
                initial_vars[var_tuple[0]] = var_tuple[1]
    return initial_vars


class Main(Application):
    def setup(self):
        self.log.info('Main RUNNING')
        self.register_service('oc-servicepoint', OCCallback)

    def teardown(self):
        self.log.info('Main FINISHED')
