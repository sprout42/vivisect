# clemency by legitbs.

from const import *
import envi
from regs import *




addr_spc = (
        (0, 0x4000000, "Main Program Memory"),
        (0x4000000, 0x1e, "Clock IO"),
        (0x4010000, 0x1000, "Flag IO"),
        (0x5000000, 0x2000, "Data Received"),
        (0x5002000, 0x3, "Data Received Size"),
        (0x5010000, 0x2000, "Data Sent"),
        (0x5012000, 0x3, "Data Sent Size"),
        (0x6000000, 0x800000, "Shared Memory"),
        (0x6800000, 0x800000, "NVRAM Memory"),
        (0x7ffff00, 0x1c, "Interrupt Pointers"),
        (0x7ffff80, 0x80, "Processor Identification and Features"),
        )

def cvt8to9(bits8):
    return (bits8 / 9), (bits8 % 9)

def cvt9to8(bits9):
    return bits9 * 9 / 8.0

'''
def make_operand_token(operand_type, reg, value):
  if operand_type == REGISTER_MODE:
    return InstructionTextToken(InstructionTextTokenType.RegisterToken, reg)
  elif operand_type == IMMEDIATE_MODE:
    return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(value), value)
'''
def mask(num):
  return (1 << num) - 1

def get_bits(value, value_size, start, end):
  return (value >> (value_size - (end + 1))) & mask(end - start + 1)



class ClmRegOper(envi.RegisterOper):
    def __init__(self, reg, va=0, oflags=0, tsize=3):
        self.va = va
        self.reg = reg
        self.oflags = oflags
        self.tsize = tsize

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.reg != oper.reg:
            return False
        if self.oflags != oper.oflags:
            return False
        return True
    
    def involvesPC(self):
        return self.reg == REG_PC

    def isDeref(self):
        return False

    def getOperValue(self, op, emu=None):
        if self.reg == REG_PC:
            return self.va

        if emu == None:
            return None
        return emu.getRegister(self.reg)

    def setOperValue(self, op, emu=None, val=None):
        if emu == None:
            return None
        emu.setRegister(self.reg, val)

    def render(self, mcanv, op, idx):
        rname = clm_regs[self.reg][0]
        mcanv.addNameText(rname, typename='registers')

    def repr(self, op):
        rname = clm_regs[self.reg][0]
        return rname

def addrToName(mcanv, va):
    sym = mcanv.syms.getSymByAddr(va)
    if sym != None:
        return repr(sym)
    return "0x%.8x" % va


class ClmImmOper(envi.ImmedOper):
    def __init__(self, val, va=0, tsize=3):
        print "immediate: %x %x %x" % (val, va, tsize)
        self.val = val
        self.tsize = tsize

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False

        if self.getOperValue(None) != oper.getOperValue(None):
            return False

        return True

    def involvesPC(self):
        return False

    def isDeref(self):
        return False

    def isDiscrete(self):
        return True

    def getOperValue(self, op, emu=None):
        return self.val

    def render(self, mcanv, op, idx):
        value = self.getOperValue(op)
        #mcanv.addNameText('#0x%.2x' % (val), typename='integers')
        #print hex(val), hex(self.val)
        hint = mcanv.syms.getSymHint(op.va, idx)
        if hint != None:
            if mcanv.mem.isValidPointer(value):
                mcanv.addVaText(hint, value)
            else:
                mcanv.addNameText(hint)
        elif mcanv.mem.isValidPointer(value):
            name = addrToName(mcanv, value)
            mcanv.addVaText(name, value)
        else:

            if self.tsize == 6:
                mcanv.addNameText("0x%.4x:0x%.8x" % (value>>32, value&0xffffffff))
            elif value >= 4096:
                mcanv.addNameText('0x%.8x' % value)
            else:
                mcanv.addNameText(str(value))

    def repr(self, op):
        val = self.getOperValue(op)
        return '#0x%.2x' % (val)

class ClmMemFlagOper(envi.ImmedOper):
    def __init__(self, flags, tsize=0):
        self.imm = flags
        self.tsize = tsize

    mem_names = [ "NONE", "R", "RW", "RX" ]
    def repr(self, op):
        return self.mem_names[self.imm]

    def render(self, mcanv, op, idx):
        flg = self.mem_names[self.imm]
        mcanv.addNameText(flg, typename="memflag")

class ClmRegListOper(envi.Operand):
    def __init__(self, base_reg, memoff, regcnt, osz=3, oflags=0):
        self.base_reg = base_reg
        self.memoff = memoff
        self.regcnt = regcnt
        self.oflags = oflags
        self.tsize = regcnt * osz
        self.osz = osz

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.base_reg != oper.base_reg:
            return False
        if self.memoff != oper.memoff:
            return False
        if self.regcnt != oper.regcnt:
            return False
        if self.oflags != oper.oflags:
            return False
        return True

    def involvesPC(self):
        return self.val & 0x80 == 0x80

    def isDeref(self):
        return True

    def render(self, mcanv, op, idx):
        mcanv.addText('[')
        mcanv.addNameText(clm_regs[self.base_reg][0], typename='registers')
        mcanv.addText(' + ')
        mcanv.addNameText(hex(self.memoff), typename='offset')
        mcanv.addText(', ')
        mcanv.addText(hex(self.regcnt))
        mcanv.addText(']')

    def getOperAddr(self, op, emu=None):
        if emu == None:
            return 

        temp = emu.getRegister(self.base_reg)
        if op.iflags & IF_D:
            temp -= self.tsize
        addr = temp + self.memoff
        return addr

    def getOperValue(self, op, emu=None):
        if emu == None:
            return None

        addr = self.getOperAddr(op, emu)

        reglist = []
        for regidx in xrange(self.regcnt):
            bytez = emu.readMemory(addr, self.osz)
            print repr(bytez)
            val = emu.parsebytes(bytez, self.osz)
            reglist.append(val)

        return reglist

    def repr(self, op):
        return "[ %s + 0x%x, 0x%x ]" % (clm_regs[self.base_reg][0], self.memoff, self.regcnt)

#''' need to wire this into the logic... non-trivial, will wait
class ClmMultiRegOper(ClmRegOper):
    def getOperValue(self, op, emu=None):
        if emu == None:
            return None
        val = emu.getRegister(self.reg)
        val <<= 27
        val |= emu.getRegister(self.reg+1)

        return val

    def __len__(self):
        return self.size*2

    def setOperValue(self, op, emu=None, val=None):
        if emu == None:
            return None

        emu.setRegister(self.reg, val & 0x3fffffff)
        emu.setRegister(self.reg + 1, (val >> 27) & 0x3fffffff)
#'''

class ClmOpcode(envi.Opcode):
    def __init__(self, va, opcode, mnem, cond, size, opers, flags, bits=0):
        self.va = va
        self.opcode = opcode
        self.mnem = mnem
        self.cond = cond
        self.size = size
        self.iflags = flags
        self.opers = opers

    def __len__(self):
        return int(self.size)

    def getBranches(self, emu=None):
        """
        Return a list of tuples.  Each tuple contains the target VA of the
        branch, and a possible set of flags showing what type of branch it is.

        See the BR_FOO types for all the supported envi branch flags....
        Example: for bva,bflags in op.getBranches():
        """
        ret = []

        '''
    if self.get_cond_name() == "":
      if self.name == "C":
        info.add_branch(BranchType.CallDestination, target)
      elif self.name == "B":
        info.add_branch(BranchType.UnconditionalBranch, target)
    else:
      if self.name == "C":
        info.add_branch(BranchType.CallDestination, target)
      elif self.name == "B":
        info.add_branch(BranchType.TrueBranch, target)
        info.add_branch(BranchType.FalseBranch, self.addr + self.SIZE)
        '''


        if not self.iflags & envi.IF_NOFALL:
            ret.append((self.va + self.size, envi.BR_FALL | envi.ARCH_CLM))

        flags = 0

        if self.getCond() != 15:
            flags |= envi.BR_COND

        if self.iflags & (envi.IF_BRANCH | envi.IF_CALL):
            oper = self.opers[0]

            # check for location being ODD
            operval = oper.getOperValue(self)
            if operval == None:
                # probably a branch to a register.  just return.
                return ret

            if self.iflags & envi.IF_CALL:
                flags |= envi.BR_PROC

            ret.append((operval, flags))

        return ret

    def getCond(self):
        return self.cond

    def render(self, mcanv):
        """
        Render this opcode to the specified memory canvas
        """

        mnem = self.mnem
        cond = self.getCond()
        if cond != 15:
            mnem += "_" + COND_NAMES[cond]

        if self.iflags & IF_SETFLAGS:
            mnem += '.'

        print mnem, repr(self.opers)
        mcanv.addNameText(mnem, typename="mnemonic")
        mcanv.addText(" ")

        # Allow each of our operands to render
        imax = len(self.opers)
        lasti = imax - 1
        for i in xrange(imax):
            oper = self.opers[i]
            print oper
            oper.render(mcanv, self, i)
            if i != lasti:
                mcanv.addText(",")

    def __repr__(self):
        mnem = self.mnem
        cond = self.getCond()
        if cond != 15:
            mnem += "_" + COND_NAMES[cond]

        if self.iflags & IF_SETFLAGS:
            mnem += '.'
        
        x = []
        
        for o in self.opers:
            x.append(o.repr(self))

        return mnem + " " + ", ".join(x)


    def get_bits(self, start, end):
      return get_bits(self.opcode, self.SIZE * 9, start, end)


class Inst(object):
  def __init__(self, addr, opcode, name, va):
    self.addr = addr
    self.opcode = opcode
    self.name = name.upper()

  def get_name(self):
    return self.name.lower()

  def add_branches(self, info):
    pass

  def get_bits(self, start, end):
    return get_bits(self.opcode, self.SIZE * 9, start, end)

  def getCondBits(self):
      return 15 

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    raise RuntimeError("Not Implemented")


class Inst54bit(Inst):
  SIZE = 6
  def conditional_sets_flags(self):
    return 0


class Inst36bit(Inst):
  SIZE = 4
  def conditional_sets_flags(self):
    return 0


class Inst27bit(Inst):
  SIZE = 3
  def conditional_sets_flags(self):
    return self.get_bits(26, 26) != 0


class Inst18bit(Inst):
  SIZE = 2
  def conditional_sets_flags(self):
    return 0


class la(Inst54bit):
  """ A combo of ML and MH """
  add_commas = True

  def __init__(self, addr, mh, ml):
    self.addr = addr
    self.reg = mh.get_operands()[0]
    self.mh = mh
    self.ml = ml
    self.name = "LA"

  def get_operands(self):
    ml_value = self.ml.get_operands()[1][1]
    mh_value = self.mh.get_operands()[1][1]

    value = (mh_value << 10) | (ml_value & 0x3ff)
    return 0, (ClmRegOper(self.reg), ClmImmOper(value))

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    first = instruction >> 27
    second = instruction & mask(27)

    ml = ra_im_al.decode(ra_im_al, "ML", Instructions["ML"][2], addr, first)
    print "--ml %s" % ml
    if ml == None:
      return None
    mh = ra_im_al.decode(ra_im_al, "MH", Instructions["MH"][2], addr, second)
    print "--mh %s" % mh
    if mh == None:
      return None

    # Make sure they're for the same register
    if mh.get_operands()[0] != ml.get_operands()[0]:
      return None
    return cls(addr, mh, ml)


class ra_rb_im(Inst27bit):
  """
    ADCI ADCIM ADI ADIM ANI DVI DVIM DVIS DVISM MDI MDIM MDIS MDISM MUI MUIM MUIS MUISM ORI
    RLI RLIM RRI RRIM SAI SAIM SBCI SBCIM SBI SBIM SLI SLIM SRI SRIM XRI
  """
    
  def get_operands(self):
    reg0 = self.get_bits(7, 11)
    reg1 = self.get_bits(12, 16)
    imm = self.get_bits(17, 23)
    uf = self.get_bits(26, 26)
    opers = (
            ClmRegOper(reg0),
            ClmRegOper(reg1),
            ClmImmOper(imm),
            )
    iflags = 0
    if uf:
        iflags = IF_SETFLAGS

    return iflags, opers

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    print hex(get_bits(instruction, 27, 0, 6)) , hex( int(values[0], 2))
    print hex(get_bits(instruction, 27, 24, 25)), hex( int(values[1], 2))
    if get_bits(instruction, 27, 0, 6) == int(values[0],2) and get_bits(instruction, 27, 24, 25) == int(values[1],2):
      return cls(addr, instruction, name, va)
    return None

MULTI_ADDRS = (
        0b0000010,
        0b0000011,
        0b0100010,
        0b0010110,
        0b101001110,
        0b10111110,
        0b10111101,
        0b10111100,
        0b0001101,
        0b0001111,
        0b0001110,
        0b101000111,
        0b101000110,
        0b0010011,
        0b0010010,
        0b001011,
        0b0001010,
        0b0001010,
        0b101001111,
        0b101001110,
        0b0011010,
        0b1000010,
        0b0110010,
        0b1000011,
        0b0110011,
        0b0111111,
        0b0101111,
        0b0100110,
        0b0000111,
        0b0111010,
        0b0101010,
        0b0111011,
        0b0101011,
        0b0011110,
        



        )

class ra_rb_rc(Inst27bit):
  """
  AD ADC ADCM ADF ADFM ADM AN ANM DMT DV DVF DVFM DVM DVS DVSM MD MDF MDFM MDM MDS MDSM MU MUF MUFM
  MUM MUS MUSM OR ORM RL RLM RR RRM SA SAM SB SBC SBCM SBF SBFM SBM SL SLM SR SRM XR XRM
  """

  def get_operands(self):
    reg0 = self.get_bits(7,11)
    reg1 = self.get_bits(12,16)
    reg2 = self.get_bits(17,21)
    uf = self.get_bits(26, 26)
    opc = self.get_bits(0, 6)

    if opc in MULTI_ADDRS:
        opers = [ClmMultiRegOper(reg) for reg in reg0, reg1, reg2]
    else:
        opers = [ClmRegOper(reg) for reg in reg0, reg1, reg2]
    iflags = 0
    if uf:
        iflags = IF_SETFLAGS

    return iflags, opers

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if get_bits(instruction, 27, 0, 6) == int(values[0],2) and get_bits(instruction, 27, 22, 25) == int(values[1],2):
      return cls(addr, instruction, name, va)
    return None

class ra_rb_me(Inst27bit):
  """ SMP """

  def get_operands(self):
    reg0 = self.get_bits(7, 11)
    reg1 = self.get_bits(12, 16)
    memflag = self.get_bits(18, 19)
    opers = 0, (
            ClmRegOper(reg0),
            ClmRegOper(reg1),
            ClmMemFlagOper(memflag),
            )
    return opers

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if (
        get_bits(instruction, 27, 0, 6) == int(values[0],2) and 
        get_bits(instruction, 27, 17, 17) == int(values[1],2) and
        get_bits(instruction, 27, 20, 26) == int(values[2],2)
      ):
      return cls(addr, instruction, name, va)
    return None

class no_re(Inst18bit):
  """ DBRK HT IR RE WT """

  def get_operands(self):
    return 0, []

  def add_branches(self, info):
    if self.name in ["RE", "IR"]:
      info.add_branch(BranchType.FunctionReturn)

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if instruction == int(values[0],2):
      return cls(addr, instruction, name, va)
    return None

class co(Inst27bit):
  """ B C """

  def get_operands(self):
    offset = self.opcode & 0xffff
    if self.opcode & 0x10000 != 0: # signed value
      offset = -(0x10000 - offset)
    return 0, (ClmImmOper(self.addr + offset), )

  def get_cond_bits(self):
    return self.get_bits(6, 9)

  def getCondBits(self):
      cond = self.get_bits(6, 9)
      return cond

  def get_cond_name(self):
    cond = self.get_cond_bits()
    return COND_NAMES[cond]

  #def get_name(self):
    #cond_name = self.get_cond_name()
    #if len(cond_name) != 0:
    #  cond_name = "_" + cond_name
    #return self.name.lower()# + cond_name

  def add_branches(self, info):
    target = self.get_operands()[0]
    if self.get_cond_name() == "":
      if self.name == "C":
        info.add_branch(BranchType.CallDestination, target)
      elif self.name == "B":
        info.add_branch(BranchType.UnconditionalBranch, target)
    else:
      if self.name == "C":
        info.add_branch(BranchType.CallDestination, target)
      elif self.name == "B":
        info.add_branch(BranchType.TrueBranch, target)
        info.add_branch(BranchType.FalseBranch, self.addr + self.SIZE)

  def conditional_sets_flags(self):
    return 0

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if get_bits(instruction, 27, 0, 5) == int(values[0],2):
      return cls(addr, instruction, name, va)
    return None

class co_ra(Inst18bit):
  """ BR CR """

  def get_operands(self):
    reg = self.get_bits(10, 14)
    return 0, (ClmRegOper(reg),)

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None) ]

  def get_cond_name(self):
    cond = self.get_bits(6, 9)
    return COND_NAMES[cond]

  def getCondBits(self):
      cond = self.get_bits(6, 9)
      return cond

  #def get_name(self):
  #  cond_name = self.get_cond_name()
  #  if len(cond_name) != 0:
  #    cond_name = "_" + cond_name
  #  return self.name.lower() + cond_name

  def add_branches(self, info):
    target = self.get_operands()[0]
    if self.get_cond_name() == "":
      if self.name == "CR":
        info.add_branch(BranchType.IndirectBranch, target)
      elif self.name == "BR":
        info.add_branch(BranchType.CallDestination, target)
    else:
      if self.name == "CR":
        info.add_branch(BranchType.CallDestination, target)
      elif self.name == "BR":
        info.add_branch(BranchType.TrueBranch, target)
        info.add_branch(BranchType.FalseBranch, self.addr + self.SIZE)

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if get_bits(instruction, 18, 0, 5) == int(values[0],2) and get_bits(instruction, 18, 15, 17) == int(values[1], 2):
      return cls(addr, instruction, name, va)
    return None

class lo(Inst36bit):
  """ BRA BRR CAA CAR """

  def is_relative(self):
    return self.name in ["BRR", "CAR"]

  def get_operands(self):
    addr = self.get_bits(9, 35)
    if self.is_relative():
      is_negative = addr & (1 << 26)
      addr &= mask(26)
      if is_negative:
        addr = -((1 << 26) - addr)
      addr += self.addr 

    return 0, (ClmImmOper(addr),)

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if get_bits(instruction, 36, 0, 8) == int(values[0],2):
      return cls(addr, instruction, name, va)
    return None

  def add_branches(self, info):
    offset = self.get_operands()[0]
    if self.name in ["BRA", "BRR"]:
      info.add_branch(BranchType.UnconditionalBranch, offset)
    elif self.name in ["CAA", "CAR"]:
      info.add_branch(BranchType.CallDestination, offset)

class ra_im(Inst27bit):
  """ CMI CMIM """

  def get_operands(self):
    reg = self.get_bits(8, 12)
    imm = self.get_bits(13, 26)
    return 0, (ClmRegOper(reg), ClmImmOper(imm))

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if get_bits(instruction, 27, 0, 7) == int(values[0],2):
      return cls(addr, instruction, name, va)
    return None

  def conditional_sets_flags(self):
    return 1


class ra_im_al(Inst27bit):
  """ MH ML MS """

  def get_operands(self):
    reg = self.get_bits(5, 9)
    if self.name == "MS":
      imm = self.get_bits(11, 26)
      if self.get_bits(10, 10): # Signed bit
        imm = -((1 << 16) - imm)
    else:
      imm = self.get_bits(10, 26)
    return 0, (ClmRegOper(reg), ClmImmOper(imm))

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if get_bits(instruction, 27, 0, 4) == int(values[0],2):
      return cls(addr, instruction, name, va)
    return None

  def conditional_sets_flags(self):
    return 0


class ra_no_fl(Inst18bit):
  """ DI EI RF SF """

  def get_operands(self):
    reg = self.get_bits(12, 16)
    return 0, (ClmRegOper(reg),)

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if get_bits(instruction, 18, 0, 11) == int(values[0],2) and get_bits(instruction, 18, 17, 17) == int(values[1],2):
      return cls(addr, instruction, name, va)
    return None


class ra_rb_lo_op(Inst27bit):
  """ BF BFM NG NGF NGFM NGM NT NTM """

  def get_operands(self):
    reg1 = self.get_bits(9, 13)
    reg2 = self.get_bits(14, 18)
    return 0, (ClmRegOper(reg1), ClmRegOper(reg2))

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if get_bits(instruction, 27, 0, 8) == int(values[0],2) and get_bits(instruction, 27, 19, 25) == int(values[1],2):
      return cls(addr, instruction, name, va)
    return None


class ra_rb_lo_ve_no_fl(Inst27bit):
  """ FTI FTIM ITF ITFM """

  def get_operands(self):
    reg1 = self.get_bits(9, 13)
    reg2 = self.get_bits(14, 18)
    return 0, (ClmRegOper(reg1), ClmRegOper(reg2))

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if get_bits(instruction, 27, 0, 8) == int(values[0],2) and get_bits(instruction, 27, 19, 26) == int(values[1],2):
      return cls(addr, instruction, name, va)
    return None

  def conditional_sets_flags(self):
    return 0


class ra_rb_lo_ve_no_fl_al(Inst27bit):
  """ RMP SES SEW ZES ZEW """

  def get_operands(self):
    reg1 = self.get_bits(7,11)
    reg2 = self.get_bits(12,16)
    return 0, (ClmRegOper(reg1), ClmRegOper(reg2))


  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if (get_bits(instruction, 27, 0, 11) == int(values[0], 2) and 
      get_bits(instruction, 27, 22, 26) == int(values[1], 2)):
      return cls(addr, instruction, name, va)
    return None

  def conditional_sets_flags(self):
    return 1


adjust_flags = [
        0,
        IF_I,
        IF_D,
        ]

class ra_rb_of_re(Inst54bit):
  """ LDS LDT LDW STS STT STW """

  def get_operands(self):
    osz = self.get_bits(5,6) + 1
    reg1 = self.get_bits(7,11)
    reg2 = self.get_bits(12,16)
    reg_count = self.get_bits(17,21)
    adjust = self.get_bits(22,23)
    offset = self.get_bits(24,50)
    oflags = adjust_flags[adjust]

    return 0, (ClmRegOper(reg1), 
            ClmRegListOper(reg2, offset, reg_count+1, osz=osz),
            )

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
      #print hex(instruction)
      #print hex(get_bits(instruction, 54, 0, 6)), hex(int(values[0],2))
      #print hex(get_bits(instruction, 54, 51, 53)), hex(int(values[1], 2))

      if (get_bits(instruction, 54, 0, 6) == int(values[0], 2) and \
          get_bits(instruction, 54, 51, 53) == int(values[1], 2)):
          return cls(addr, instruction, name, va)
      return None



class ra_rb_sh_ve(Inst18bit):
  """ CM CMF CMFM CMM """

  def get_operands(self):
    reg1 = self.get_bits(8,12)
    reg2 = self.get_bits(13,17)
    return 0, (ClmRegOper(reg1), ClmRegOper(reg2))

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    if get_bits(instruction, 18, 0, 7) == int(values[0], 2):
      return cls(addr, instruction, name, va)
    return None



class ra_wi_fl(Inst27bit):
  """ RND RNDM """

  def get_operands(self):
    reg1 = self.get_bits(9,13)
    return 0, (ClmRegOper(reg1),)

  @staticmethod
  def decode(cls, name, values, addr, instruction, va=0):
    #print hex(get_bits(instruction, 27, 0, 8)) , hex( int(values[0], 2))
    #print hex(get_bits(instruction, 27, 14, 25)), hex( int(values[1], 2))
    if (get_bits(instruction, 27, 0, 8) == int(values[0], 2)
      and get_bits(instruction, 27, 14, 25) == int(values[1], 2)):
      return cls(addr, instruction, name, va)
    return None



p_map = {}
for pnm in ptypes:
    p_map[eval(pnm)] = globals().get(pnm.lower())

class ClmDisasm:
    def disasm(self, bytez, off, va):
        cond = 0

        bytes_per_size = {}
        found = []

        #for mnem, (size, inst_type, values, flags) in Instructions.items():
        for mnem in InstructionKeys:
            (size, inst_type, values, flags) = Instructions[mnem]
            
            size /= 9
            if size not in bytes_per_size:
                value = read_memory_value(bytez[off:off+size])
                #print hex(value)
                bytes_per_size[size] = value

            parser = p_map.get(inst_type)
            #print "parser: %r" % parser
            if parser == None:
                print "WTF!  parser == None, for %s" % inst_type

            #print "values: %r\tbytes_per_size: %x" % (values, bytes_per_size[size])
            inst = parser.decode(parser, mnem, values, va, bytes_per_size[size])
            #print "\treturned: %r" % inst
            if inst != None:
                found.append((inst, flags))
                print "found: %x: %s  (%r)" % (va, mnem, parser)

        if len(found) > 1:
            for inst in found:
                if inst.name == "LA":
                    return inst
            raise RuntimeError("Multiple instructions found {}".format([x.__class__.__name__ for x in found]))
        elif len(found) == 0:
            print("Unknown instruction decoding (%x) {}".format([x.__class__.__name__ for x in found]) % va)
            return None

        meta, flags = found[0]
        nflags, olist = meta.get_operands()
        flags |= nflags

        if flags & envi.IF_COND:
            cond = meta.getCondBits()
        else:
            cond = 15

        if flags & envi.IF_BRANCH and cond==15:
            flags |= IF_NOFALL

        opcode = globals().get("INS_" + mnem.upper())
        mnem = meta.get_name()

        if meta.conditional_sets_flags():
            flags |= IF_SETFLAGS


        #print "COND: %d" % cond
        op = ClmOpcode(va, opcode, mnem, cond, meta.SIZE, olist, flags)

        return op

    def readBytes(self, mem, off, size):
        # deprecated in favor of storing 9-bit numbers in MemoryObject... this could be a fatal decision and we may have to come back to this...
        realoff, realbitoff, rsize = self.getAddrBits(off, size)

        data = []
        pbyte = mem[coff]
        for idx in range(off):
            byte = mem[coff] >> realbitoff

    def getAddrBits(self, off, size):
        base = off * 9
        realoffset = base / 8
        realbitoff = base % 8

        rsize = size * 9

        return realoffset, realbitoff, rsize


    def setEndian(self, endian):
        pass
    

def read_memory_value(bytez):
    size = len(bytez)

    if size == 1:
        value  = bytez[0]
        #print "only: %r" % (value)
    elif size == 2:
        least = bytez[0]
        most  = bytez[1]
        #print "least: %r\tmost: %r" % (least, most)
        value = (most << 9) | least
    elif size == 3:
        middle = bytez[0]
        most   = bytez[1]
        least  = bytez[2]
        #print "least: %r\tmost: %r\tmiddle: %r" % (least, most, middle)
        value = (most << 18) | (middle << 9) | least
    elif size == 4:
        first = read_memory_value(bytez[:3])
        second = read_memory_value(bytez[3:])
        #print "first: %r\tsecond: %r" % (first, second)
        value = (first << 9) | second
    elif size == 6:
        first = read_memory_value(bytez[:3])
        second = read_memory_value(bytez[3:])
        #print "first: %r\tsecond: %r" % (first, second)
        value = (first << 27) | second
    else: 
        print "Unknown size!  %s" % size
    return value

