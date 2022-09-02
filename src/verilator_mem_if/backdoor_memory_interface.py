# Copyright IDEX Biometrics
# Licensed under the MIT License, see LICENSE
# SPDX-License-Identifier: MIT

import logging
import socket
import struct
from time import sleep
from typing import (Callable, Sequence, Union)
from ._version import version as plugin_version
from .conversion import *

LOG = logging.getLogger(__name__)

class BackdoorMemoryInterface:
    """@brief A backdoor memory interface for use with a simulation model. 
    
    Each read/write request has two phases, a header and a payload.  The header defines
    the transaction and should match the C struct as defined by:

    struct __attribute__ ((__packed__)) Request {
      unsigned int   address;
      unsigned short size;
      unsigned char  rnw;
    };

    where the fields are defined as follows:

      address : the byte address of the access
      size    : the number of bytes to write or read
      rnw     : read-not-write bit (read = 1)

    A write access comprises the header, the data payload and an acknowledge byte.

    A read access comprises the header and a data payload only.
    
    """

    WRITE = 0x0
    READ  = 0x1
    ACK   = 0x15

    def __init__(self, hostname: str = "localhost", port: int = 5557) -> None:
        self._hostname = hostname
        self._port = int(port)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def connect(self):
        try:
            self._sock.connect((self._hostname, self._port))
            LOG.debug(f"connected to {self._hostname}:{self._port}")
        except Exception as e:
            LOG.error(f"socket connect() failed when using {self._hostname}:{self._port}")
            raise e

    def close(self):
        self._sock.close()

    def write_memory(self, addr: int, data: int, transfer_size: int = 32, **kwargs) -> None:
        """@brief Write a single memory location. """
        assert transfer_size in (8, 16, 32)
        addr &= 0xffffffff
        if transfer_size == 32:
            self._write_mem8(addr, u32le_list_to_byte_list([data]))
        elif transfer_size == 16:
            self._write_mem8(addr, u16le_list_to_byte_list([data]))
        elif transfer_size == 8:
            self._write_mem8(addr, [data])

    def read_memory(self, addr: int, transfer_size: int = 32, now: bool = True, **kwargs) -> Union[int, Callable[[], int]]:
        """@brief Read a single memory location. """
        assert transfer_size in (8, 16, 32)
        addr &= 0xffffffff
        if transfer_size == 32:
            result = byte_list_to_u32le_list(self._read_mem8(addr, 4))[0]
        elif transfer_size == 16:
            result = byte_list_to_u16le_list(self._read_mem8(addr, 2))[0]
        elif transfer_size == 8:
            result = self._read_mem8(addr, 1)[0]

        def read_callback():
            return result
        return result if now else read_callback

    def write_memory_block32(self, addr: int, data: Sequence[int]) -> None:
        """@brief Write an aligned block of 32-bit words."""
        self._write_mem8(addr, u32le_list_to_byte_list(data))

    def read_memory_block32(self, addr: int, size: int) -> Sequence[int]:
        """@brief Read an aligned block of 32-bit words."""
        return byte_list_to_u32le_list(self._read_mem8(addr, size*4))

    def write_memory_block8(self, addr: int, data: Sequence[int]) -> None:
        """@brief Write a block of bytes. """
        self._write_mem8(addr, data)

    def read_memory_block8(self, addr: int, size: int) -> Sequence[int]:
        """@brief Read a block of bytes. """
        return self._read_mem8(addr, size)

    def _write_mem8(self, addr: int, data: Sequence[int]):
        assert isinstance(data, Sequence), "`data` must be byte Sequence"
        self._send_header(addr, len(data), self.WRITE)
        self._send_payload(bytearray(data))

    def _read_mem8(self, addr: int, size: int) -> Sequence[int]:
        self._send_header(addr, size, self.READ)
        return self._recv_payload(size)

    def _send_header(self, addr: int, size: int, rnw: int) -> None:
        header = (addr, size, rnw)
        self._sock.sendall(struct.pack('I H B', *header))

    def _send_payload(self, bytes: bytearray):
        self._sock.sendall(bytes)
        self._recv_ack()

    def _recv_payload(self, size: int) -> Sequence[int]:
        return self._recv_bytes(size)

    def _recv_ack(self) -> None:
        ack = self._recv_bytes(1)[0]
        assert ack == self.ACK, "invalid ACK received, got %s" % ack

    def _recv_bytes(self, size: int) -> Sequence[int]:
        data = bytearray()
        while (len(data) < size):
            n = self._sock.recv(1024)
            data += n
        return list(data)
