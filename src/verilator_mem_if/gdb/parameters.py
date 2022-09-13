# Copyright IDEX Biometrics
# Licensed under the MIT License, see LICENSE
# SPDX-License-Identifier: MIT

import gdb
import re
import ipaddress

def valid_ip_address(ip):
    if ip == 'localhost':
        return True
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def valid_port(port):
    if re.match(r"^\d+$", port):
        return True
    return False

class BackdoorUid(gdb.Parameter):
    """This parameter stores the pyOCD UID that identifies the DebugProbe.
    
    """
    def __init__(self):
        """Another doc"""
        super().__init__("bd-uid", gdb.COMMAND_DATA, gdb.PARAM_STRING)
        self.show_doc = "UID: "
        self.value = "localhost:5557"
        self.saved_value = self.value

    def validate(self):
        """The UID must be of the type localhost:port or ip_addr:port. """
        try:
            ip,port = self.value.split(':')
            if not valid_ip_address(ip) or not valid_port(port):
                return False
            return True
        except ValueError:
            return False

    def get_set_string(self):
        if not self.validate():
            self.value = self.saved_value
            raise gdb.GdbError("failed to validate bd-uid")
        self.saved_value = self.value
        return f"set UID to {self.value}"

BackdoorUid()
