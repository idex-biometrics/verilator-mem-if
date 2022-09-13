# Copyright IDEX Biometrics
# Licensed under the MIT License, see LICENSE
# SPDX-License-Identifier: MIT

import verilator_mem_if.gdb as _gdb

@_gdb.register(prefix=True)
class Bd(_gdb.Command):
    """This is the main Backdoor prefix command, it does nothing. """
    def run(self, args):
        pass

with _gdb.register.prefix("bd"):
    import verilator_mem_if.gdb.extensions.memory