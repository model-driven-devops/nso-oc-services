#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ncclient import manager


m = manager.connect_ssh(host="X.X.X.X",
                        port=2022, username='admin',
                        password='xxx',
                        hostkey_verify=False)
config = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <oc-system-nso xmlns="http://cisco.com/oc-system-nso">
    <name>R1</name>
    <device>R1</device>
    <oc-sys>
      <system>
        <config>
            <hostname>R1</hostname>
            <domain-name>www.cisco.com</domain-name>
            <login-banner>This is line 1.\nThis is line 2.\nThis is the last line.</login-banner>
            <motd-banner>This is line 1.\nThis is line 2.\nThis is the last line.</motd-banner>
        </config>
      </system>
    </oc-sys>
  </oc-system-nso>
</config>
"""
result = m.edit_config(target='running', config=config)
print(result)

m.close_session()
