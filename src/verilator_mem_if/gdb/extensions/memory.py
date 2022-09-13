# Copyright IDEX Biometrics
# Licensed under the MIT License, see LICENSE
# SPDX-License-Identifier: MIT

import gdb
import sys
from pathlib import Path
from contextlib import contextmanager
import verilator_mem_if.gdb as _gdb
from verilator_mem_if import BackdoorMemoryInterface
from intelhex import IntelHex
from veriloghex import VerilogHex
from bincopy import BinFile

debug = True

@contextmanager
def file_or_stdout(file):
    if file is None:
        yield sys.stdout
    else:
        with Path(file).open('w') as f:
            yield f

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
            type=int,
            help="specify the starting address"
        )
        parser.add_argument(
            "size",
            type=int,
            help="specify the number of bytes to dump"
        )
        parser.add_argument(
            "-f",
            "--format",
            choices=["intel", "verilog", "hex"],
            default="hex",
            help="the dump format to use"
        )
        parser.add_argument(
            "-o",
            "--output",
            default=None,
            help="basename of optional output file (extension: OUTPUT.[hex,vmem,ihex])"
        )

    def run(self, args):
        if debug:
            print(f"> args={args}")

        hostname,port = gdb.parameter('bd-uid').split(':')
        with BackdoorMemoryInterface(hostname, port) as bd:
            data = bd.read_memory_block8(args.address, args.size)
        
        try:
            filename = args.output + "." + self.extensions[args.format]
        except KeyError:
            raise gdb.GdbError(f"unexpected format {args.format}")
        except TypeError:
            filename = None

        with file_or_stdout(filename) as f:
            if args.format == "verilog":
                vmem = VerilogHex(data, offset=args.address)
                a = vmem.tovmem()
                f.write(a)
            elif args.format in ['intel', 'hex']:
                ihex = IntelHex()
                ihex.frombytes(data)
                if args.format == 'hex':
                    ihex.dump(f)
                else:
                    ihex.tofile(f, 'hex')
                


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

    def run(self, args):
        path = Path(args.filename)
        format = args.format or path.suffix.replace('.','')
        if format not in ['hex', 'vmem']:
            raise gdb.GdbError(f"unrecognised file extension '{format}'")

        hostname,port = gdb.parameter('bd-uid').split(':')
        with BackdoorMemoryInterface(hostname, port) as bd:
            hex = BinFile(str(path)) if format == 'hex' else VerilogHex(str(path))
            for address,data in hex:
                bd.write_memory_block8(address,data)
