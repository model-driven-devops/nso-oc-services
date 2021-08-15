from typing import Tuple
import re


def xe_get_interface_type_and_number(interface: str) -> Tuple[str, str]:
    """
    Receive full interface name. Returns interface type and number.
    :param interface: full interface name
    :return: tuple of interface type, interface number
    """
    rt = re.search(r"\D+", interface)
    interface_name = rt.group(0)
    rn = re.search(r"[0-9]+(\/[0-9]+)*", interface)
    interface_number = rn.group(0)
    return interface_name, interface_number
