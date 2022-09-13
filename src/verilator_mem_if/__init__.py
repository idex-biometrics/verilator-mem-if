# Copyright IDEX Biometrics
# Licensed under the MIT License, see LICENSE
# SPDX-License-Identifier: MIT

try:
    from ._version import __version__
except ImportError:
    __version__ = "unknown"

from .backdoor_memory_interface import BackdoorMemoryInterface