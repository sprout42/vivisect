
"""
The initial clm module.
"""

import envi

from envi.archs.clm.regs import *
from envi.archs.clm.disasm import *

class ClmModule(envi.ArchitectureModule):

    def __init__(self, name='clmv6'):
        import envi.archs.thumb16.disasm as eatd
        # these are required for setEndian() which is called from ArchitectureModule.__init__()
        self._arch_dis = ClmDisasm()

        envi.ArchitectureModule.__init__(self, name, maxinst=4)
        self._arch_reg = self.archGetRegCtx()

    def archGetRegCtx(self):
        return ClmRegisterContext()

    def archGetBreakInstr(self):
        return

    def archGetNopInstr(self):
        return '\x00'
 
    def getPointerSize(self):
        return 3

    def pointerString(self, va):
        return "0x%.8x" % va

    def archParseOpcode(self, bytes, offset=0, va=0):
        """
        Parse a sequence of bytes out into an envi.Opcode instance.
        """
        return self._arch_dis.disasm(bytes, offset, va)

    def getEmulator(self):
        emu = ClmEmulator()
        emu.setMemArchitecture(envi.ARCH_CLM)

    def setEndian(self, endian):
        self._endian = endian
        self._arch_dis.setEndian(endian)

    def archModifyFuncAddr(self, va, info):
        return va, {}

    def archModifyXrefAddr(self, tova, reftype, rflags):
        return tova, reftype, rflags




#from envi.archs.clm.emu import *
