# Copyright IDEX Biometrics
# Licensed under the MIT License, see LICENSE
# SPDX-License-Identifier: MIT

import re, logging
from typing import (Sequence, Union, Optional)
from pathlib import Path

LOG = logging.getLogger(__file__)

class VerilogHexSegment:
    """ Represents a segment of data at a specific address.

    """
    def __init__(self, 
                 bytes: Optional[Union[Sequence[int], str]] = None, 
                 offset: Optional[Union[int, str]] = 0
                 ) -> None:
        """ Initialize a new segment.

        Arg: offset  A hex address offset for the word
        Arg: bytes  An empty string or a whitespace separated list of words

        """
        self._bytes  = []
        self._offset = offset if isinstance(offset, int) else int(offset, 16)

        if bytes:
            self.append(bytes)

    def append(self, bytes: Union[Sequence[int], str]) -> None:
        """ This method appends a list of bytes to the segment.

        The argument |bytes| can either be a sequence of integers representing each byte
        or a string in Verilog Hex format.  For the latter, it is expected that the string
        contains white space separated hex values in any byte width, e.g.:

            01 23 45 67 89 AB CD EF
            67452301 EFCDAB89

        """
        if isinstance(bytes, list):
            self._bytes.extend(bytes)

        elif isinstance(bytes, str):
            # ignore any blank lines
            if re.match(r"^\s*$", bytes): 
                return

            # strip off any leading/trailing white space
            bytes = bytes.rstrip().lstrip()

            # iterate over each word in the string and extend the byte array
            for word in bytes.split(' '):
                # split the string into a list of bytes
                bytes = re.findall(r"[0-9A-Fa-f]{2}", word)
                # reverse the list so that we are in little endian
                bytes.reverse()
                # append to the main array
                self._bytes.extend([int(b,16) for b in bytes])
        else:
            raise ValueError(f"unsupported type passed to append: {type(bytes)}")

    @property
    def size(self):
        """ Returns the size of the segment in bytes. """
        return len(self._bytes)

    @property
    def end(self):
        """ Returns the end address of the segment (exclusive) """
        return self._offset + self.size

    @property
    def has_address(self, address):
        """ Returns true if the address sits within the segment. """
        # REVISIT: cope with int, string types, convert from hex
        return address >= self._offset and address < self.end

    def tohex(self, width_bytes: int = 4):
        """Returns a list of strings in Verilog hex format. """
        hex = []
        offset = self._offset
        # Iterate over slices of |width_bytes| bytes
        for bytes in zip(*(iter(self._bytes),) * width_bytes):
            # Convert the ints in to LE hex strings
            word = ''.join(['{:02x}'.format(b) for b in reversed(bytes)])
            # Concatenat the word with its offset
            hex.append(f"@{offset:08x} {word}")
            # Increment the RAM offset
            offset += 1
        return hex



class VerilogHex:
    """ A class for reading and writing Verilog hex files.

    This class has methods for loading from and dumping to hex files in a format
    supported by the Verilog $readmemh function.

    """
    def __init__(self, 
                 source: Optional[Union[Sequence[int], str]] = None, 
                 offset: Optional[int] = 0
                 ):
        """If source is defined, then we populate the segments. 
        


        """
        self._segments = []

        if source is not None:
            if isinstance(source, str):
                self.loadhex(source)
            elif isinstance(source, Sequence):
                self.frombytes(source, offset)
            else:
                raise ValueError("unrecognised source type")

    def frombytes(self, bytes: Sequence[int], offset: Optional[int] = 0) -> None:
        """Load from a sequence of bytes. 
        
        The sequence must contain int values representing a byte.  An optional offset
        allows sparse segements to be constructed.
        
        """
        self._segments.append(VerilogHexSegment(bytes, offset))

    def loadhex(self, fobj):
        """Load from a Verilog hex file.
        
        This method parses a Verilog Hex file and extracts all segments.
        
        """

        try:
            line = fobj.readline()
        except AttributeError:
            fobj = Path(fobj).open()
            line = fobj.readline()        

        segment = None
        while line:
            if re.search(r"^\s*/\*", line):
                line = fobj.readline()
                continue

            # Look for offset markers of the form @hexoffset
            match = re.match(r"""\s*
                                    @([0-9A-Fa-f]+)
                                    \s*
                                    (.*?)
                                    \n
                                """, line, re.X )
            if match:
                # Seen a new segment, stash the previous one.
                if segment is not None: 
                    self._segments.append(segment)

                # Initialize a new segment with 
                (offset,bytes) = match.groups()
                LOG.debug(f"offset={offset}, bytes={bytes}")
                segment = VerilogHexSegment(bytes,offset)

            # Look for any more bytes in the segment
            match = re.match(r"""([A-Fa-f0-9\s]+)
                                    \n
                                """, line, re.X )
            if match:
                # Append more bytes to the segment
                segment.add_bytes(match.group(1))

            # Continue onto the next line
            line = fobj.readline()

        if segment is None:
            raise RuntimeError("segment cannot be None")

        # Push the last captured onto the list
        self._segments.append(segment)

        fobj.close()


    def to_hex(self, word_size):
        for segment in self._segments:
            segment.write_words(word_size=word_size)


    def dump(self):
        for segment in self._segments:
            for s in segment.tohex():
                print(s)