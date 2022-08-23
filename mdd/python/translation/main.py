# -*- mode: python; python-indent: 4 -*-
from re import compile

from _ncs import TransCtxRef
from ncs.maagic import Root, ListElement
from ncs.application import Application, Service

from translation.openconfig_xe.xe_main import check_xe_features
from translation.openconfig_xr.xr_main import check_xr_features

regex_device = compile(r'device{(.*)}\/')

class OCCallback(Service):
    @Service.create
    def cb_create(self, tctx: TransCtxRef, root: Root, service: ListElement, proplist: list):
        self.log.info(f'Service create(service={service._path})')
        self.service = service
        self.root = root
        self.proplist = proplist
        # Get device name from service path
        r = regex_device.search(service._path)
        self.device_name = r.group(1)

        # Each NED may have a template and will have python processing code
        if 'cisco-ios-cli' in self.root.devices.device[self.device_name].device_type.cli.ned_id:
            check_xe_features(self)
        elif 'cisco-iosxr-cli' in self.root.devices.device[self.device_name].device_type.cli.ned_id:
            check_xr_features(self)

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
