from envi import *
from envi.archs.riscv.regs import *
from envi.archs.riscv.const import *
from envi.archs.riscv.disasm import *
from envi.archs.riscv.info import *

from envi.archs.riscv import RiscVModule


__all__ = [
    'RiscVCall',
    'RiscVAbstractEmulator',
    'RiscVEmulator',
]



class RiscVCall(envi.CallingConvention):
    '''
    RiscV Calling Convention.
    '''
    arg_def = [
        (CC_REG, REG_A0),
        (CC_REG, REG_A1),
        (CC_REG, REG_A2),
        (CC_REG, REG_A3),
        (CC_REG, REG_A4),
        (CC_REG, REG_A5),
        (CC_REG, REG_A6),
        (CC_REG, REG_A7),
    ]
    arg_def.append((CC_STACK_INF, 8))
    retaddr_def = (CC_REG, REG_RA)
    retval_def = [
        (CC_REG, REG_A0), (CC_REG, REG_A1)
    ]
    flags = CC_CALLEE_CLEANUP
    align = 16
    pad = 0


class RiscVAbstractEmulator(envi.Emulator):
    def __init__(self, archmod=None, endian=ENDIAN_LSB, description=None):
        if description is None:
            self.description = DEFAULT_RISCV_DESCR
        else:
            self.description = description
        self.xlen = getRiscVXLEN(self.description)
        self.psize = self.xlen // 8
        super().__init__(archmod=archmod)
        self.setEndian(endian)
        self.addCallingConvention("riscvcall", RiscVCall)


class RiscVEmulator(RiscVRegisterContext, RiscVModule, RiscVAbstractEmulator):
    def __init__(self, archmod=None, endian=ENDIAN_LSB, description=None):
        RiscVModule.__init__(self, endian=endian, description=description)
        RiscVAbstractEmulator.__init__(self, archmod=self, endian=endian, description=description)
        RiscVRegisterContext.__init__(self, description)
