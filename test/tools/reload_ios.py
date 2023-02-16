#! /usr/bin/env python3
import os
import paramiko
import time


def reload(ip, username, password):
    retry = 3
    while retry > 0:
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(ip, port=22, username=username, password=password, look_for_keys=False,
                      allow_agent=False)
            ssh = c.invoke_shell()
            ssh.send('reload\n')
            time.sleep(1)
            ssh.recv(65535)
            time.sleep(1)
            ssh.send('yes\n')
            time.sleep(1)
            ssh.recv(65535)
            time.sleep(1)
            ssh.send('\n')
            time.sleep(1)
            ssh.recv(65535)
            time.sleep(60)
            ssh.close()
            return
        except Exception as e:
            print(e)
            retry -= 1


if __name__ == "__main__":
    user = os.environ.get("NSO_DEVICES_USERNAME", "admin")
    pwd = os.environ.get("NSO_DEVICES_PASSWORD", "admin")
    device = os.environ.get("XESWITCH1_HOST")
    reload(device, user, pwd)
