# Copyright IDEX Biometrics
# Licensed under the MIT License, see LICENSE
# SPDX-License-Identifier: MIT

import sys, argparse, intelhex
from pathlib import Path
from intelhex import IntelHex
from veriloghex import VerilogHex

from .backdoor_memory_interface import BackdoorMemoryInterface
from . import __version__

def dumpmem(hostname: str, port: int, address: int, size: int, ):
    with BackdoorMemoryInterface(hostname, port) as bd:
        data = bd.read_memory_block8(address,size)
        print(data)

def validate_address(astring):
    try:
        return int(astring,0)
    except ValueError:
        raise argparse.ArgumentError("expecting a hex string or integer for the address")


def load(args):
    print(args)
    with Path(args.filename).open() as f:
        try:
            ih = IntelHex(f)
        except Exception as e:
            raise e from None
            


def dump(args):
    print(args)
    with BackdoorMemoryInterface(args.hostname, args.port) as bd:
        bytes = bd.read_memory_block8(args.address, args.size)
        vmem = VerilogHex(bytes)
        vmem.dump()

formatter = lambda prog: argparse.RawTextHelpFormatter(prog, max_help_position=80, width=200)

def parse_args():
    parser = argparse.ArgumentParser(
        description="A script for loading and dumping memory",
        formatter_class=formatter
    )
    subparsers = parser.add_subparsers()

    # Global options
    parser.add_argument(
        "--version",
        action="version",
        version=__version__,
        help="display the version"
    )
    parser.add_argument(
        "--hostname", 
        default="localhost", 
        type=str, 
        help="specify the hostname to connect to (default: %(default)s)"
    )
    parser.add_argument(
        "--port",
        default=5557,
        type=int,
        help="specify the port (default: %(default)s)"
    )

    # load subparser
    parser_load = subparsers.add_parser(
        "load",
        help="load memory from a file"
    )
    parser_load.add_argument(
        "filename",
        help="specify the input file name"
    )
    parser_load.set_defaults(func=load)

    # dump parser
    parser_dump = subparsers.add_parser(
        "dump",
        help="dump memory to a file or stdout"
    )
    parser_dump.add_argument(
        "address",
        type=validate_address,
        help="the memory address to dump"
    )
    parser_dump.add_argument(
        "size",
        type=int,
        help="number of bytes to transfer"
    )
    parser_dump.add_argument(
        "--format",
        default="vmem",
        choices=["vmem", "ihex"],
        help="specify the output format (default: %(default)s)"
    )
    parser_dump.add_argument(
        "--vmem-width",
        type=int,
        default=32,
        choices=[8, 16, 32, 64, 128],
        help="specify the bit width for VMEM output (default: %(default)s)"
    )
    parser_dump.add_argument(
        "--output",
        type=str,
        help="dump to a file instead of STDOUT"
    )
    parser_dump.set_defaults(func=dump)

    args = parser.parse_args()

    if hasattr(args, "func"):
        return args
    if hasattr(args, "subparser"):
        args.subparser.print_help()
    else:
        parser.print_help()
        return None

def main():
    args = parse_args()
    if not args:
        exit(0)
    
    args.func(args)

    # if args.version:
    #     print(__version__)
    #     sys.exit(0)

if __name__ == "__main__":
    main()