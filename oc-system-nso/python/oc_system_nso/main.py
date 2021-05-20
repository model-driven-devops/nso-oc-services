# -*- mode: python; python-indent: 4 -*-
import ncs
from ncs.application import Service


class ServiceCallbacks(Service):
    @staticmethod
    def transform_vars(service_object) -> list:
        proplist = list()
        if service_object.openconfig_system.system.clock.config.timezone_name:
            tz = service_object.openconfig_system.system.clock.config.timezone_name.split()
            if len(tz) != 3:
                raise ValueError
            else:
                proplist.append(('TIMEZONE', tz[0]))
            if -12 > int(tz[1]) or int(tz[1]) > 12:
                raise ValueError
            else:
                proplist.append(('TIMEZONE_OFFSET_HOURS', tz[1]))
            if 0 > int(tz[2]) or int(tz[2]) > 60:
                raise ValueError
            else:
                proplist.append(('TIMEZONE_OFFSET_MINUTES', tz[2]))

        return proplist

    @Service.create
    def cb_create(self, tctx, root, service, proplist):
        self.log.info('Service create(service=', service._path, ')')

        initial_vars = dict(TIMEZONE='',
                            TIMEZONE_OFFSET_HOURS='',
                            TIMEZONE_OFFSET_MINUTES='')

        final_vars = self.update_vars(initial_vars, proplist)
        vars_template = ncs.template.Variables()
        for k in final_vars:
            vars_template.add(k, final_vars[k])
        template = ncs.template.Template(service)
        template.apply('oc-system-nso-template', vars_template)

    @Service.pre_modification
    def cb_pre_modification(self, tctx, op, kp, root, proplist):
        self.log.info(f'Service premod(service={kp})')
        if op == ncs.dp.NCS_SERVICE_CREATE:
            service = ncs.maagic.cd(root, kp)
            proplist = self.transform_vars(service)
        elif op == ncs.dp.NCS_SERVICE_DELETE:
            self.log.info('Service premod(operation=NCS_SERVICE_DELETE, skip)')
        return proplist

    @staticmethod
    def update_vars(initial_vars: dict, proplist: list) -> dict:
        if proplist:
            for var_tuple in proplist:
                if var_tuple[0] in initial_vars:
                    initial_vars[var_tuple[0]] = var_tuple[1]
        return initial_vars


class Main(ncs.application.Application):
    def setup(self):
        self.log.info('Main RUNNING')
        self.register_service('oc-system-nso-servicepoint', ServiceCallbacks)

    def teardown(self):
        self.log.info('Main FINISHED')
