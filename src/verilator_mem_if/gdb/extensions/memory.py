# Copyright IDEX Biometrics
# Licensed under the MIT License, see LICENSE
# SPDX-License-Identifier: MIT

import gdb
from contextlib import contextmanager
import verilator_mem_if.gdb as _gdb
from verilator_mem_if.backdoor import (
    int_from_dec_or_hex_string, init, load, dump, IllegalFormatError
)

@_gdb.register("dump")
class BackdoorDump(_gdb.UserCommand):
    """Write contents of memory to a hex file.

    """
    extensions = {
        'verilog': 'vmem',
        'intel'  : 'hex',
        'binary' : 'bin',
        'hex'    : 'dump',
    }

    def setup(self, parser):
        parser.add_argument(
            "address",
            type=int_from_dec_or_hex_string,
            help="memory address to dump"
        )
        parser.add_argument(
            "size",
            type=int_from_dec_or_hex_string,
            help="number of bytes to dump"
        )
        parser.add_argument(
            "-f",
            "--format",
            choices=["intel", "verilog", "hex"],
            default="hex",
            help="the dump format to use (default: %(default)s)"
        )
        parser.add_argument(
            "--vmem-width",
            type=int,
            default=32,
            choices=[8, 16, 32, 64, 128],
            help="specify the bit width for VMEM output (default: %(default)s)"
        )
        parser.add_argument(
            "-o",
            "--output",
            type=str,
            default=None,
            help="dump to file instead of STDOUT"
        )
        hostname,port = gdb.parameter('bd-uid').split(':')
        parser.set_defaults(hostname=hostname, port=port)

    def run(self, args):
        try:
            dump(args)
        except Exception as e:
            raise gdb.GdbError(e)


@_gdb.register("load")
class BackdoorLoad(_gdb.UserCommand):
    """Write contents of a hex file to memory.

    Currently supportd the Verilog and Intel hex file formats.

    """
    def setup(self, parser):
        parser.add_argument(
            "filename",
            help="the Verilog or Intel hex file to parse"
        )
        parser.add_argument(
            "-f",
            "--format",
            choices=["intel", "verilog"],
            help="override the file type detection"
        )
        hostname,port = gdb.parameter('bd-uid').split(':')
        parser.set_defaults(hostname=hostname, port=port)

    def run(self, args):
        try:
            load(args)
        except IllegalFormatError as e:
            raise gdb.GdbError(e)
        except Exception as e:
            raise gdb.GdbError(f"unexpected exception: {e}")



@_gdb.register("init")
class BackdoorInitMemory(_gdb.UserCommand):
    """Initialize the contents of a memory to a known value.
    
    The RAM models used for the flash default to a reset value of 0x00 which differs from the
    erased flash state of 0xFF.  This method provides the user with a single command that can
    be used to initialize the flash, or any memory for that matter, to a known value.

    The intent is that this command would be called before loading the program to memory, for
    example, by running `arm-none-eabi-gdb -iex "bd init 0x0 0x40000" [gdb options]`

    """
    def setup(self, parser):
        parser.add_argument(
            "--init-value",
            type=int_from_dec_or_hex_string,
            default="0xff",
            help="byte value to use for flash initialization (default: %(default)s)"
        )
        parser.add_argument(
            "--address",
            default=0x800000,
            type=int_from_dec_or_hex_string,
            help="specify the start address of the flash (default: %(default)s)"
        )
        parser.add_argument(
            "--size",
            default=0x80000,
            type=int_from_dec_or_hex_string,
            help="specify the size of the flash in bytes (default: %(default)s)"
        )
        hostname,port = gdb.parameter('bd-uid').split(':')
        parser.set_defaults(hostname=hostname, port=port)

    def run(self, args):
        init(args)
