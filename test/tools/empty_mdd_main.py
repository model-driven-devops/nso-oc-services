# -*- mode: python; python-indent: 4 -*-
import ncs
import _ncs
from ncs.application import Service


class OCCallback(Service):
    @Service.create
    def cb_create(self, tctx: _ncs.TransCtxRef, root: ncs.maagic.Root, service: ncs.maagic.ListElement, proplist: list):
        pass


class Main(ncs.application.Application):
    def setup(self):
        self.log.info('Main RUNNING')
        self.register_service('oc-servicepoint', OCCallback)

    def teardown(self):
        self.log.info('Main FINISHED')
