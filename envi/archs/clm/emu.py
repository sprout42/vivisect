import sys
import struct
import logging

import envi
import envi.bits as e_bits
from envi.const import *
from regs import *
from envi.archs.clm import ClmModule

logger = logging.getLogger(__name__)

# CPU state (memory, regs inc SPSRs and banked registers)
# CPU mode  (User, FIQ, IRQ, supervisor, Abort, Undefined, System)
# 
# instruction code
# exception handler code
# FIXME: SPSR handling is not certain.  

# calling conventions
class ClmArchitectureProcedureCall(envi.CallingConvention):
    arg_def = [(CC_REG, REG_R0), (CC_REG, REG_R1), (CC_REG, REG_R2),
                (CC_REG, REG_R3), (CC_REG, REG_R4), (CC_REG, REG_R5), 
                (CC_REG, REG_R6), (CC_REG, REG_R7), (CC_STACK_INF, 4),]
    retaddr_def = (CC_REG, REG_R14)
    retval_def = (CC_REG, REG_R0)
    flags = CC_CALLEE_CLEANUP
    align = 9
    pad = 0

clmpcs = ClmArchitectureProcedureCall()


def c0000(flags):
    return not (flags & FL_Z)

def c0001(flags):
    return flags & FL_Z

def c0010(flags):
    return (flags & FL_C) and not (flags & FL_Z)

def c0011(flags):
    return (flags & FL_C) or (flags & FL_Z)

def c0100(flags):
    return not ((flags & FL_C) or (flags & FL_Z))

def c0101(flags):
    return not (flags & FL_C) or (flags & FL_Z)

def c0110(flags):
    return not (flags & FL_O)

def c0111(flags):
    return flags & FL_O

def c1000(flags):
    return not (flags & FL_S)

def c1001(flags):
    return flags & FL_S

def c1010(flags):
    return (flags & FL_S) | (flags & FL_O) != (FL_S | FL_O)

def c1011(flags):
    return c1010(flags) or flags & FL_Z

def c1100(flags):
    return c1101(flags) and not (flags & FL_Z)   # C == O AND Z==0

def c1101(flags):
    return bool(flags & FL_S) == bool(flags & FL_O)

def c1111(flags):
    return True


conditionals = [
        c0000,
        c0001,
        c0010,
        c0011,
        c0100,
        c0101,
        c0110,
        c0111,
        c1000,
        c1001,
        c1010,
        c1011,
        c1100,
        c1101,
        None,
        c1111,
        ]

class ClmEmulator(ClmModule, ClmRegisterContext, envi.Emulator):

    def __init__(self):
        ClmModule.__init__(self)

        seglist = [ (0,0xffffffff) for x in xrange(6) ]
        envi.Emulator.__init__(self, ClmModule())

        ClmRegisterContext.__init__(self)

        self.addCallingConvention("clmcall", clmpcs)

    def undefFlags(self):
        """
        Used in PDE.
        A flag setting operation has resulted in un-defined value.  Set
        the flags to un-defined as well.
        """
        self.setRegister(REG_FL, None)

    def setFlag(self, which, state):
        flags = self.getRegister(REG_FL)
        if state:
            flags |= which
        else:
            flags &= ~which
        self.setRegister(REG_FL, flags)

    def getFlag(self, which):          # FIXME: CPSR?
        flags = self.getRegister(REG_FL)
        if flags == None:
            raise envi.PDEUndefinedFlag(self)
        return bool(flags & which)

    def readMemValue(self, addr, size):
        bytes = self.readMemory(addr, size)
        if bytes == None:
            return None
        if len(bytes) != size:
            raise Exception("Read Gave Wrong Length At 0x%.8x (va: 0x%.8x wanted %d got %d)" % (self.getProgramCounter(),addr, size, len(bytes)))

        val = 0
        for x in range(size):
            val << 9
            val |= bytes[x]

    def writeMemValue(self, addr, value, size):
        #FIXME change this (and all uses of it) to passing in format...
        #FIXME: Remove byte check and possibly half-word check.  (possibly all but word?)
        bytes = []
        for x in range(size):
            val = value >> (x*9) & 0x1f
            bytes.insert(0, val)

        self.writeMemory(addr, bytes)

    def readMemSignedValue(self, addr, size):
        #FIXME: Remove byte check and possibly half-word check.  (possibly all but word?)
        return self.readMemValue(addr, size)

    def executeOpcode(self, op):
        # NOTE: If an opcode method returns
        #       other than None, that is the new eip
        x = None
        cond = op.cond
        if conditionals[cond](self.getRegister(REG_FL) & 0xf):
            meth = self.op_methods.get(op.mnem, None)
            if meth == None:
                raise envi.UnsupportedInstruction(self, op)
            x = meth(op)

        if x == None:
            pc = self.getProgramCounter()
            x = pc+op.size

        self.setProgramCounter(x)

    def doPush(self, val):
        st = self.getRegister(REG_ST)
        st -= 3
        self.writeMemValue(st, val, 3)
        self.setRegister(REG_ST, st)

    def doPop(self):
        st = self.getRegister(REG_ST)
        val = self.readMemValue(st, 3)
        self.setRegister(REG_ST, st+3)
        return val

    def getRegister(self, index):
        """
        Return the current value of the specified register index.
        """
        idx = (index & 0xffff)
        if idx == index:
            return self._rctx_vals[idx]

        offset = (index >> 24) & 0xff
        width  = (index >> 16) & 0xff

        mask = (2**width)-1
        return (self._rctx_vals[idx] >> offset) & mask

    def setRegister(self, index, value, mode=None):
        """
        Set a register value by index.
        """
        self._rctx_dirty = True

        idx = (index & 0xffff)

        if idx == index:    # not a metaregister
            self._rctx_vals[idx] = (value & self._rctx_masks[idx])      # FIXME: hack.  should look up index in proc_modes dict?
            return

        # If we get here, it's a meta register index.
        # NOTE: offset/width are in bits...
        offset = (index >> 24) & 0xff
        width  = (index >> 16) & 0xff

        #FIXME is it faster to generate or look thses up?
        mask = (2**width)-1
        mask = mask << offset

        # NOTE: basewidth is in *bits*
        basewidth = self._rctx_widths[idx]
        basemask  = (2**basewidth)-1

        # cut a whole in basemask at the size/offset of mask
        finalmask = basemask ^ mask

        curval = self._rctx_vals[idx]

        self._rctx_vals[idx] = (curval & finalmask) | (value << offset)

    def integerSubtraction(self, op):
        """
        Do the core of integer subtraction but only *return* the
        resulting value rather than assigning it.
        (allows cmp and sub to use the same code)
        """
        # Src op gets sign extended to dst
        #FIXME account for same operand with zero result for PDE
        src1 = self.getOperValue(op, 1)
        src2 = self.getOperValue(op, 2)
        setflags = op.iflags & IF_SETFLAGS

        if src1 == None or src2 == None:
            self.undefFlags()
            return None

        return self.intSubBase(src1, src2, setflags)

    def intSubBase(self, src1, src2, size, setflags=0, rd=0):
        # So we can either do a BUNCH of crazyness with xor and shifting to
        # get the necessary flags here, *or* we can just do both a signed and
        # unsigned sub and use the results.

        udst = unsigned(src1, size)
        usrc = unsigned(src2, size)

        sdst = signed(src1, size)
        ssrc = signed(src2, size)

        ures = udst - usrc
        sres = sdst - ssrc

        if setflags:
            self.setFlag(FL_S_bit, ures >> (size))
            self.setFlag(FL_Z_bit, not ures)
            self.setFlag(FL_C_bit, not is_unsigned_carry(ures, size))
            self.setFlag(FL_O_bit, is_signed_overflow(sres, size))

        return ures

    def logicalAnd(self, op):
        src1 = self.getOperValue(op, 1)
        src2 = self.getOperValue(op, 2)

        # PDE
        if src1 == None or src2 == None:
            self.undefFlags()
            self.setOperValue(op, 0, None)
            return

        res = src1 & src2

        self.setFlag(FL_S_bit, 0)
        self.setFlag(FL_Z_bit, not res)
        self.setFlag(FL_C_bit, 0)
        self.setFlag(FL_O_bit, 0)
        return res


    def i_ad(self, op): 
        dsize = op.opers[0].tsize

        src1 = self.getOperValue(op, 1)
        src2 = self.getOperValue(op, 2)

        udst = unsigned(src1, dsize)
        usrc = unsigned(src2, dsize)

        sdst = signed(src1, dsize)
        ssrc = signed(src2, dsize)

        ures = udst + usrc
        sres = sdst + ssrc

        # PDE
        if src1 == None or src2 == None:
            self.undefFlags()
            self.setOperValue(op, 0, None)
            return

        self.setOperValue(op, 0, ures)

        if (op.iflags & IF_SETFLAGS): self.doFlags(ures, sres, dsize)

    def i_adc(self, op):
        dsize = op.opers[0].tsize

        src1 = self.getOperValue(op, 1)
        src2 = self.getOperValue(op, 2)
        C = self.getFlag(FL_C_bit)

        udst = unsigned(src1, dsize)
        usrc = unsigned(src2, dsize)

        sdst = signed(src1, dsize)
        ssrc = signed(src2, dsize)

        ures = udst + usrc + C
        sres = sdst + ssrc + C

        # PDE
        if src1 == None or src2 == None:
            self.undefFlags()
            self.setOperValue(op, 0, None)
            return

        self.setOperValue(op, 0, ures)

        if (op.iflags & IF_SETFLAGS): self.doFlags(ures, sres, dsize)

    i_adci = i_adc

    def i_adcim(self, op):
        dsize = op.opers[0].tsize * 2

        srcreg = op.opers[1].reg
        dstreg = op.opers[0].reg

        src1 = self.getRegister(srcreg)
        src1 += self.getRegister(srcreg + 1)

        src2 = self.getOperValue(op, 2)
        C = self.getFlag(FL_C_bit)

        udst = unsigned(src1, dsize * 2)
        usrc = unsigned(src2, dsize)

        sdst = signed(src1, dsize)
        ssrc = signed(src2, dsize)

        ures = udst + usrc + C
        sres = sdst + ssrc + C

        # PDE
        if src1 == None or src2 == None:
            self.undefFlags()
            self.setOperValue(op, 0, None)
            return

        self.setRegister(dstreg, ures & 0x7fffffff)
        self.setRegister(dstreg+1, (ures>>27) & 0x7fffffff)

        self.setFlag(FL_S_bit, is_signed(ures, dsize))
        self.setFlag(FL_Z_bit, not ures)
        self.setFlag(FL_C_bit, is_unsigned_carry(ures, dsize))
        self.setFlag(FL_O_bit, is_signed_overflow(sres, dsize))

    def doFlags(self, ures, sres, dsize):
        self.setFlag(FL_S_bit, is_signed(ures, dsize))
        self.setFlag(FL_Z_bit, not ures)
        self.setFlag(FL_C_bit, is_unsigned_carry(ures, dsize))
        self.setFlag(FL_O_bit, is_signed_overflow(sres, dsize))

    #def i_adcm(self, op): pass 
    #def i_adf(self, op): pass 
    #def i_adfm(self, op): pass 
    i_adi = i_ad

    #def i_adim(self, op): pass 
    #def i_adm(self, op): pass 
    #def i_an(self, op): pass 
    #def i_ani(self, op): pass 
    #def i_anm(self, op): pass 
    #def i_b(self, op): pass 
    #def i_bf(self, op): pass 
    #def i_bfm(self, op): pass 
    #def i_br(self, op): pass 
    #def i_bra(self, op): pass 
    #def i_brr(self, op): pass 
    #def i_c(self, op): pass 
    #def i_caa(self, op): pass 
    #def i_car(self, op): pass 
    #def i_cm(self, op): pass 
    #def i_cmf(self, op): pass 
    #def i_cmfm(self, op): pass 
    #def i_cmi(self, op): pass 
    #def i_cmim(self, op): pass 
    #def i_cmm(self, op): pass 
    #def i_cr(self, op): pass 
    #def i_dbrk(self, op): pass 
    #def i_di(self, op): pass 
    #def i_dmt(self, op): pass 
    #def i_dv(self, op): pass 
    #def i_dvf(self, op): pass 
    #def i_dvfm(self, op): pass 
    #def i_dvi(self, op): pass 
    #def i_dvim(self, op): pass 
    #def i_dvis(self, op): pass 
    #def i_dvism(self, op): pass 
    #def i_dvm(self, op): pass 
    #def i_dvs(self, op): pass 
    #def i_dvsm(self, op): pass 
    #def i_ei(self, op): pass 
    #def i_fti(self, op): pass 
    #def i_ftim(self, op): pass 
    #def i_ht(self, op): pass 
    #def i_ir(self, op): pass 
    #def i_itf(self, op): pass 
    #def i_itfm(self, op): pass 
    #def i_lds(self, op): pass 
    def i_ldt(self, op):
        src = self.getOperValue(op, 1)
        regidx = op.opers[0].reg
        
        for val in src:
            self.setRegister(regidx, val)
            regidx += 1
            regidx %= 32

    #def i_ldw(self, op): pass 
    #def i_md(self, op): pass 
    #def i_mdf(self, op): pass 
    #def i_mdfm(self, op): pass 
    #def i_mdi(self, op): pass 
    #def i_mdim(self, op): pass 
    #def i_mdis(self, op): pass 
    #def i_mdism(self, op): pass 
    #def i_mdm(self, op): pass 
    #def i_mds(self, op): pass 
    #def i_mdsm(self, op): pass 
    #def i_mh(self, op): pass 
    def i_ml(self, op):
        src = self.getOperValue(op, 1)
        self.setOperValue(op, 0, src)
        if op.iflags & IF_SETFLAGS: self.doFlags(src, src, op.opers[1].tsize)

    #def i_ms(self, op): pass 
    def i_mu(self, op):
        dsize = op.opers[0].tsize

        src1 = self.getOperValue(op, 1)
        src2 = self.getOperValue(op, 2)

        udst = unsigned(src1, dsize)
        usrc = unsigned(src2, dsize)

        sdst = signed(src1, dsize)
        ssrc = signed(src2, dsize)

        ures = udst * usrc
        sres = sdst * ssrc


        # PDE
        if src1 == None or src2 == None:
            self.undefFlags()
            self.setOperValue(op, 0, None)
            return

        self.setOperValue(op, 0, ures)
        if op.iflags & IF_SETFLAGS: self.doFlags(ures, sres, dsize)

    #def i_muf(self, op): pass 
    #def i_mufm(self, op): pass 
    #def i_mui(self, op): pass 
    #def i_muim(self, op): pass 
    #def i_muis(self, op): pass 
    #def i_muism(self, op): pass 
    #def i_mum(self, op): pass 
    #def i_mus(self, op): pass 
    #def i_musm(self, op): pass 
    #def i_ng(self, op): pass 
    #def i_ngf(self, op): pass 
    #def i_ngfm(self, op): pass 
    #def i_ngm(self, op): pass 
    #def i_nt(self, op): pass 
    #def i_ntm(self, op): pass 
    #def i_or(self, op): pass 
    #def i_ori(self, op): pass 
    #def i_orm(self, op): pass 
    #def i_re(self, op): pass 
    #def i_rf(self, op): pass 
    #def i_rl(self, op): pass 
    #def i_rli(self, op): pass 
    #def i_rlim(self, op): pass 
    #def i_rlm(self, op): pass 
    #def i_rmp(self, op): pass 
    #def i_rnd(self, op): pass 
    #def i_rndm(self, op): pass 
    #def i_rr(self, op): pass 
    #def i_rri(self, op): pass 
    #def i_rrim(self, op): pass 
    #def i_rrm(self, op): pass 
    #def i_sa(self, op): pass 
    #def i_sai(self, op): pass 
    #def i_saim(self, op): pass 
    #def i_sam(self, op): pass 
    i_sb = integerSubtraction
        
    def i_sbc(self, op):
        src1 = self.getOperValue(op, 1)
        src2 = self.getOperValue(op, 2)
        setflags = op.iflags & IF_SETFLAGS
        C = self.getFlag(FL_C_bit)

        if src1 == None or src2 == None:
            self.undefFlags()
            return None

        return self.intSubBase(src1, src2-C, setflags)

    i_sbci = i_sbc
    #def i_sbcim(self, op): pass 
    #def i_sbcm(self, op): pass 
    #def i_sbf(self, op): pass 
    #def i_sbfm(self, op): pass 
    #def i_sbi(self, op): pass 
    #def i_sbim(self, op): pass 
    #def i_sbm(self, op): pass 
    #def i_ses(self, op): pass 
    #def i_sew(self, op): pass 
    #def i_sf(self, op): pass 
    #def i_sl(self, op): pass 
    #def i_sli(self, op): pass 
    #def i_slim(self, op): pass 
    #def i_slm(self, op): pass 
    def i_smp(self, op): 
        print "setting memory perms: (not really):  %s" % op

    #def i_sr(self, op): pass 
    #def i_sri(self, op): pass 
    #def i_srim(self, op): pass 
    #def i_srm(self, op): pass 
    #def i_sts(self, op): pass 
    #def i_stt(self, op): pass 
    #def i_stw(self, op): pass 
    #def i_wt(self, op): pass 
    #def i_xr(self, op): pass 
    #def i_xri(self, op): pass 
    #def i_xrm(self, op): pass 
    #def i_zes(self, op): pass 
    #def i_zew(self, op): pass 

    def buildbytes(self, val, size):
        bytez = []

        # do it straight first.
        for x in range(size):
            bytez.insert(0, val & 0x1ff)
            val >>= 9

        if size > 4:
            tmp = bytez[3]
            bytez[3] = bytez[4]
            bytez[4] = tmp

        if size > 1:
            tmp = bytez[0]
            bytez[0] = bytez[1]
            bytez[1] = tmp

        return bytez

    def parsebytes(self, bytez, size):
        out = 0

        if size == 1:
            return bytez[0]

        if size == 2:
            val = bytez[1]
            val <<= 9
            val |= bytez[0]
            return val

        elif size == 3:
            val = bytez[1]
            val <<= 9
            val |= bytez[0]
            val <<= 9
            val |= bytez[2]
            return val

        if size == 4:
            val = bytez[1]
            val <<= 9
            val |= bytez[0]
            val <<= 9
            val |= bytez[2]
            val <<= 9
            val |= bytez[4]
            return val

        if size == 5:
            val = bytez[1]
            val <<= 9
            val |= bytez[0]
            val <<= 9
            val |= bytez[2]
            val <<= 9
            val |= bytez[4]
            val <<= 9
            val |= bytez[3]
            return val
       
        if size == 6:
            val = bytez[1]
            val <<= 9
            val |= bytez[0]
            val <<= 9
            val |= bytez[2]
            val <<= 9
            val |= bytez[4]
            val <<= 9
            val |= bytez[3]
            val <<= 9
            val |= bytez[5]
            return val


MAX_WORD = 32 # usually no more than 9, 16 is for SIMD register support

# Masks to use for unsigned anding to size
u_maxes = [ (2 ** (9*i)) - 1 for i in range(MAX_WORD+1) ]
u_maxes[0] = 0 # powers of 0 are 1, but we need 0
bu_maxes = [ (2 ** (i)) - 1 for i in range(9*MAX_WORD+1) ]

# Masks of just the sign bit for different sizes
sign_bits = [ (2 ** (9*i)) >> 1 for i in range(MAX_WORD+1) ]
sign_bits[0] = 0 # powers of 0 are 1, but we need 0
bsign_bits = [ (2 ** i)>>1 for i in range(9*MAX_WORD+1) ]

# Max *signed* masks (all but top bit )
s_maxes = [ u_maxes[i] ^ sign_bits[i] for i in range(len(u_maxes))]
s_maxes[0] = 0

# bit width masks 
b_masks = [ (2**i)-1 for i in range(MAX_WORD*9) ]
b_masks[0] = 0

def unsigned(value, size):
    """
    Make a value unsigned based on it's size.
    """
    return value & u_maxes[size]

def signed(value, size):
    """
    Make a value signed based on it's size.
    """
    x = unsigned(value, size)
    if x & sign_bits[size]:
        x = (x - u_maxes[size]) - 1
    return x

def is_signed(value, size):
    x = unsigned(value, size)
    return bool(x & sign_bits[size])

def sign_extend(value, cursize, newsize):
    """
    Take a value and extend it's size filling
    in the space with the value of the high 
    order bit.
    """
    x = unsigned(value, cursize)
    if cursize != newsize:
        # Test for signed w/o the call
        if x & sign_bits[cursize]:
            delta = newsize - cursize
            highbits = u_maxes[delta]
            x |= highbits << (9*cursize)
    return x

def bsign_extend(value, cursize, newsize):
    x = value
    if cursize != newsize:
        if x & bsign_bits[cursize]:
            delta = newsize - cursize
            highbits = bu_maxes[delta]
            x |= highbits << (cursize)
    return x
  
def is_parity(val):
    s = 0
    while val:
        s ^= val & 1
        val = val >> 1
    return (not s)

parity_table = []
for i in range(256):
    parity_table.append(is_parity(i))

def is_parity_byte(bval):
    """
    An "optimized" parity checker that looks up the index.
    """
    return parity_table[bval & 0xff]

def lsb(value):
    return value & 0x1

def msb(value, size):
    if value & sign_bits[size]:
        return 1
    return 0

def is_signed_half_carry(value, size, src):
    '''
    BCD carry/borrow in the second most important nibble:
        32bit   - bit 27
        16bit   - bit 11
        8bit    - bit 3
    '''
    bitsize = (size << 3) - 5
    mask = 1<<bitsize

    p1 = value & mask
    p2 = src & mask
    
    return ((p1 ^ p2) != 0)

def is_signed_carry(value, size, src):
    smax = s_maxes[size]
    if value > smax > src:
        return True
    if value < -smax < -src:
        return True
    return False

def is_signed_overflow(value, size):
    smax = s_maxes[size]
    if value > smax:
        return True
    if value < -smax:
        return True
    return False

def is_unsigned_carry(value, size):
    umax = u_maxes[size]
    if value > umax:
        return True
    elif value < 0:
        return True
    return False

