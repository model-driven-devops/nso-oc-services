#! /usr/bin/env python3
import os
import paramiko
import time


def check_device_response(ip, username, password, max_retries=120, delay=5):
    for i in range(max_retries):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=10)
            return True
        except paramiko.AuthenticationException as e:
            print(f"Authentication failed: {e}")
            break
        except paramiko.SSHException as e:
            print(f"Unable to establish SSH connection: {e}")
            time.sleep(delay)
        except TimeoutError as e:
            print(f"Unable to establish SSH connection: {e}")
            time.sleep(delay)
    return False


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
            output = ssh.recv(65535)
            print(output)
            time.sleep(1)
            ssh.send('yes\n')
            time.sleep(1)
            output = ssh.recv(65535)
            print(output)
            time.sleep(1)
            ssh.send('\n')
            time.sleep(1)
            output = ssh.recv(65535)
            print(output)
            ssh.send('\n')
            time.sleep(1)
            output = ssh.recv(65535)
            print(output)
            time.sleep(1)
            ssh.close()
            return True
        except Exception as e:
            print(e)
            retry -= 1
    return False


if __name__ == "__main__":
    user = os.environ.get("NSO_DEVICES_USERNAME", "admin")
    pwd = os.environ.get("NSO_DEVICES_PASSWORD", "admin")
    device = os.environ.get("XESWITCH1_HOST")
    if reload(device, user, pwd):
        check_device_response(device, user, pwd)
