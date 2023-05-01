'''
Parser objects for the SRECORD file format.
'''
import logging
import binascii

import envi.const as e_const

import vstruct
from vstruct.primitives import *


logger = logging.getLogger(__name__)


S0_HEADER = 0
S1_DATA = 1
S2_DATA = 2
S3_DATA = 3
S4_RESERVED = 4
S5_COUNT = 5
S6_COUNT = 6
S7_STARTADDR = 7
S8_STARTADDR = 8
S9_STARTADDR = 9
SCOMMENT = 10


SREC_ADDR_RANGES = {
    S0_HEADER: range(1, 3),
    S1_DATA: range(1, 3),
    S2_DATA: range(1, 4),
    S3_DATA: range(1, 5),
    S5_COUNT: range(1, 3),
    S6_COUNT: range(1, 4),
    S7_STARTADDR: range(1, 5),
    S8_STARTADDR: range(1, 4),
    S9_STARTADDR: range(1, 3),
}

SREC_ADDR_SHIFTS = {
    S0_HEADER: (8, 0),
    S1_DATA: (8, 0),
    S2_DATA: (16, 8, 0),
    S3_DATA: (24, 16, 8, 0),
    S5_COUNT: (8, 0),
    S6_COUNT: (16, 8, 0),
    S7_STARTADDR: (24, 16, 8, 0),
    S8_STARTADDR: (16, 8, 0),
    S9_STARTADDR: (8, 0),
}

def get_srec_addr(data, code):
    return sum(data[i] << s for s, i in zip(SREC_ADDR_SHIFTS[code], SREC_ADDR_RANGES[code]))

class SRecFile:
    '''
    One or more chunks of binary data
    '''
    def __init__(self):
        self.chunks         = []
        self.entrypoints    = []

    def vsParse(self, data, offset=0):
        '''
        Custom parsing for the SRecord type
        '''
        for line in data[offset:].splitlines(keepends=True):
            # We use keepends so we can know exactly how many bytes have been
            # parsed
            offset += len(line)

            line = line.strip()
            # out of spec, but common: treat lines which don't begin with 'S' as
            # comments
            if line and line[0] == 'S':
                rtype = int(line[1])
                line_bytes = bytes.fromhex(line[2:])
                addr = get_srec_addr(line_bytes, rtype)

                if rtype in (S1_DATA, S2_DATA, S3_DATA):
                    data_start = SREC_ADDR_RANGES[rtype].stop
                    self.chunks.append((addr, line_bytes[data_start:-1]))
                elif rtype in (S7_STARTADDR, S8_STARTADDR, S9_STARTADDR):
                    self.entrypoints.append(addr)
                    break

        return offset

    def vsEmit(self, fast=False):
        '''
        Get back the byte sequence associated with this structure. For the SREC
        file just return all of the data chunks concatenated together.
        '''
        return b''.join(c for _, c in sorted(self.chunks))

    def getEntryPoints(self):
        '''
        If a 32bit linear start address is defined for this file,
        return it.  Returns None if the 32bit entry point extension
        is not present.
        '''
        return self.entrypoints

    def getMemoryMaps(self):
        '''
        Retrieve a set of memory maps defined by this hex file.

        Memory maps are returned as a list of
        ( va, perms, fname, data ) tuples.
         '''
        memparts = {}
        offset_to_base = {}

        for offset, data in sorted(self.chunks):
            if offset not in offset_to_base:
                memparts[offset] = bytearray(data)
                offset_to_base[offset+len(data)] = offset
            else:
                base = offset_to_base[offset]
                memparts[base] += data
                del offset_to_base[offset]
                offset_to_base[base+len(memparts[base])] = base

        maps = []
        for addr, data in sorted(memparts.items()):
            maps.append( [ addr, e_const.MM_RWX, '', bytes(data) ] )
        return maps

