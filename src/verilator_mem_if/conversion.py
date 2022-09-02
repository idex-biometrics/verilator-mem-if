# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
# Copyright (c) 2021 Chris Reed
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct
import binascii
from typing import (Any, Iterator, Sequence, Tuple, cast)

ByteList = Sequence[int]

def byte_list_to_u32le_list(data: ByteList, pad: int = 0x00) -> Sequence[int]:
    """@brief Convert a list of bytes to a list of 32-bit integers (little endian)

    If the length of the data list is not a multiple of 4, then the pad value is used
    for the additional required bytes.
    """
    res = []
    for i in range(len(data) // 4):
        res.append(data[i * 4 + 0] |
                   data[i * 4 + 1] << 8 |
                   data[i * 4 + 2] << 16 |
                   data[i * 4 + 3] << 24)
    remainder = (len(data) % 4)
    if remainder != 0:
        padCount = 4 - remainder
        res += byte_list_to_u32le_list(list(data[-remainder:]) + [pad] * padCount)
    return res

def u32le_list_to_byte_list(data: Sequence[int]) -> ByteList:
    """@brief Convert a word array into a byte array"""
    res = []
    for x in data:
        res.append((x >> 0) & 0xff)
        res.append((x >> 8) & 0xff)
        res.append((x >> 16) & 0xff)
        res.append((x >> 24) & 0xff)
    return res

def u16le_list_to_byte_list(data: Sequence[int]) -> ByteList:
    """@brief Convert a halfword array into a byte array"""
    byteData = []
    for h in data:
        byteData.extend([h & 0xff, (h >> 8) & 0xff])
    return byteData

def byte_list_to_u16le_list(byteData: ByteList) -> Sequence[int]:
    """@brief Convert a byte array into a halfword array"""
    data = []
    for i in range(0, len(byteData), 2):
        data.append(byteData[i] | (byteData[i + 1] << 8))
    return data