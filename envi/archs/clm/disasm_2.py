import struct

def read_memory_value(bytez):
    size = len(bytez)

    if size == 1:
        value  = bytez
    elif size == 2:
        least = bytez[0]
        most  = bytez[1]
        value = (most << 9) | least
    elif size == 3:
        middle = bytez[0]
        most   = bytez[1]
        least  = bytez[2]
        value = (most << 18) | (middle << 9) | least
    elif size == 4:
        first = read_memory_value(bytez[:3])
        second = read_memory_value(bytez[3:])
        value = (first << 9) | second
    elif size == 6:
        first = read_memory_value(bytez[:3])
        second = read_memory_value(bytez[3:])
        value = (first << 27) | second
    return value






def make_operand_token(operand_type, reg, value):
  if operand_type == REGISTER_MODE:
    return InstructionTextToken(InstructionTextTokenType.RegisterToken, reg)
  elif operand_type == IMMEDIATE_MODE:
    return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(value), value)

def mask(num):
  return (1 << num) - 1

def get_bits(value, value_size, start, end):
  return (value >> (value_size - (end + 1))) & mask(end - start + 1)

class Inst(object):
  def __init__(self, addr, opcode, name):
    self.addr = addr
    self.opcode = opcode
    self.name = name.upper()

  def get_name(self):
    return self.name.lower()

  def add_branches(self, info):
    pass

  def get_bits(self, start, end):
    return get_bits(self.opcode, self.SIZE * 9, start, end)

  @staticmethod
  def decode(cls, name, values, addr, instruction):
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

class ra_rb_im(Inst27bit):
  """
    ADCI ADCIM ADI ADIM ANI DVI DVIM DVIS DVISM MDI MDIM MDIS MDISM MUI MUIM MUIS MUISM ORI
    RLI RLIM RRI RRIM SAI SAIM SBCI SBCIM SBI SBIM SLI SLIM SRI SRIM XRI
  """
    
  def get_operands(self):
    reg0 = self.get_bits(7, 11)
    reg1 = self.get_bits(12, 16)
    imm = self.get_bits(17, 23)
    return reg0, reg1, imm

  def get_operand_tokens(self):
    operands = self.get_operands()
    tokens = []
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None))
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None))
    tokens.append(make_operand_token(IMMEDIATE_MODE, None, operands[2]))
    return tokens

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 6) == int(values[0],2) and get_bits(instruction, 27, 24, 25) == int(values[1],2):
      return cls(addr, instruction, name)
    return None

class ra_rb_rc(Inst27bit):
  """
  AD ADC ADCM ADF ADFM ADM AN ANM DMT DV DVF DVFM DVM DVS DVSM MD MDF MDFM MDM MDS MDSM MU MUF MUFM
  MUM MUS MUSM OR ORM RL RLM RR RRM SA SAM SB SBC SBCM SBF SBFM SBM SL SLM SR SRM XR XRM
  """

  def get_operands(self):
    reg0 = self.get_bits(7,11)
    reg1 = self.get_bits(12,16)
    reg2 = self.get_bits(17,21)
    return reg0, reg1, reg2

  def get_operand_tokens(self):
    operands = self.get_operands()
    tokens = []
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None))
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None))
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[2]], None))
    return tokens

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 6) == int(values[0],2) and get_bits(instruction, 27, 22, 25) == int(values[1],2):
      return cls(addr, instruction, name)
    return None

class ra_rb_me(Inst27bit):
  """ SMP """

  def get_operands(self):
    reg0 = self.get_bits(7, 11)
    reg1 = self.get_bits(12, 16)
    memflag = self.get_bits(18, 19)
    return reg0, reg1, memflag

  def get_operand_tokens(self):
    mem_names = [ "NONE", "R", "RW", "RX" ]
    operands = self.get_operands()
    tokens = []
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None))
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None))
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, mem_names[operands[2]]))
    return tokens

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if (
        get_bits(instruction, 27, 0, 6) == int(values[0],2) and 
        get_bits(instruction, 27, 17, 17) == int(values[1],2) and
        get_bits(instruction, 27, 20, 26) == int(values[2],2)
      ):
      return cls(addr, instruction, name)
    return None

class no_re(Inst18bit):
  """ DBRK HT IR RE WT """

  def get_operands(self):
    return []

  def get_operand_tokens(self):
    return []

  def add_branches(self, info):
    if self.name in ["RE", "IR"]:
      info.add_branch(BranchType.FunctionReturn)

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if instruction == int(values[0],2):
      return cls(addr, instruction, name)
    return None

class co(Inst27bit):
  """ B C """

  def get_operands(self):
    offset = self.opcode & 0xffff
    if self.opcode & 0x10000 != 0: # signed value
      offset = -(0x10000 - offset)
    return self.addr + offset,

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ make_operand_token(IMMEDIATE_MODE, None, operands[0]) ]

  def get_cond_name(self):
    cond = self.get_bits(6, 9)
    return COND_NAMES[cond]

  def get_name(self):
    cond_name = self.get_cond_name()
    if len(cond_name) != 0:
      cond_name = "_" + cond_name
    return self.name.lower() + cond_name

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
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 5) == int(values[0],2):
      return cls(addr, instruction, name)
    return None

class co_ra(Inst18bit):
  """ BR CR """

  def get_operands(self):
    reg = self.get_bits(10, 14)
    return reg,

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None) ]

  def get_cond_name(self):
    cond = self.get_bits(6, 9)
    return COND_NAMES[cond]

  def get_name(self):
    cond_name = self.get_cond_name()
    if len(cond_name) != 0:
      cond_name = "_" + cond_name
    return self.name.lower() + cond_name

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
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 18, 0, 5) == int(values[0],2) and get_bits(instruction, 18, 15, 17) == int(values[1], 2):
      return cls(addr, instruction, name)
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

    return addr,

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ make_operand_token(IMMEDIATE_MODE, None, operands[0]) ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 36, 0, 8) == int(values[0],2):
      return cls(addr, instruction, name)
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
    return reg, imm

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ 
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(IMMEDIATE_MODE, None, operands[1]),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 7) == int(values[0],2):
      return cls(addr, instruction, name)
    return None

  def conditional_sets_flags(self):
    return 1


class ra_im_al(Inst27bit):
  """ MH ML MS """

  def get_operands(self):
    reg = self.get_bits(5, 9)
    imm = self.get_bits(10, 26)
    return reg, imm

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ 
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(IMMEDIATE_MODE, None, operands[1]),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 4) == int(values[0],2):
      return cls(addr, instruction, name)
    return None

  def conditional_sets_flags(self):
    return 0


class ra_no_fl(Inst18bit):
  """ DI EI RF SF """

  def get_operands(self):
    reg = self.get_bits(12, 16)
    return reg,

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ 
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 18, 0, 11) == int(values[0],2) and get_bits(instruction, 18, 17, 17) == int(values[1],2):
      return cls(addr, instruction, name)
    return None


class ra_rb_lo_op(Inst27bit):
  """ BF BFM NG NGF NGFM NGM NT NTM """

  def get_operands(self):
    reg1 = self.get_bits(9, 13)
    reg2 = self.get_bits(14, 18)
    return reg1, reg2

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ 
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 8) == int(values[0],2) and get_bits(instruction, 27, 19, 25) == int(values[1],2):
      return cls(addr, instruction, name)
    return None


class ra_rb_lo_ve_no_fl(Inst27bit):
  """ FTI FTIM ITF ITFM """

  def get_operands(self):
    reg1 = self.get_bits(9, 13)
    reg2 = self.get_bits(14, 18)
    return reg1, reg2

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ 
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 8) == int(values[0],2) and get_bits(instruction, 27, 19, 26) == int(values[1],2):
      return cls(addr, instruction, name)
    return None

  def conditional_sets_flags(self):
    return 0


class ra_rb_lo_ve_no_fl_al(Inst27bit):
  """ RMP SES SEW ZES ZEW """

  def get_operands(self):
    reg1 = self.get_bits(7,11)
    reg2 = self.get_bits(12,16)
    return reg1, reg2

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ 
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if (get_bits(instruction, 27, 0, 6) == int(values[0], 2) and 
      get_bits(instruction, 27, 17, 26) == int(values[1], 2)):
      return cls(addr, instruction, name)
    return None

  def conditional_sets_flags(self):
    return 1



class ra_rb_of_re(Inst54bit):
  """ LDS LDT LDW STS STT STW """

  def get_operands(self):
    reg1 = self.get_bits(7,11)
    reg2 = self.get_bits(12,16)
    reg_count = self.get_bits(17,21)
    adjust = self.get_bits(22,23)
    offset = self.get_bits(24,50)
    return reg1, reg2, reg_count, adjust, offset

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ 
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None),
      make_operand_token(IMMEDIATE_MODE, None, operands[2]),
      make_operand_token(IMMEDIATE_MODE, None, operands[3]),
      make_operand_token(IMMEDIATE_MODE, None, operands[4]),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if (get_bits(instruction, 54, 0, 6) == int(values[0], 2) and 
      get_bits(instruction, 54, 51, 53) == int(values[1], 2)):
      return cls(addr, instruction, name)
    return None



class ra_rb_sh_ve(Inst18bit):
  """ CM CMF CMFM CMM """

  def get_operands(self):
    reg1 = self.get_bits(8,12)
    reg2 = self.get_bits(13,17)
    return reg1, reg2

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 18, 0, 7) == int(values[0], 2):
      return cls(addr, instruction, name)
    return None



class ra_wi_fl(Inst27bit):
  """ RND RNDM """

  def get_operands(self):
    reg1 = self.get_bits(9,13)
    return reg1,

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if (get_bits(instruction, 27, 0, 8) == int(values[0], 2)
      and get_bits(instruction, 27, 14, 25) == int(values[0], 2)):
      return cls(addr, instruction, name)
    return None


Instructions = {
  'AD' : (ra_rb_rc, ['000000', '0000']),
  'ADC' : (ra_rb_rc, ['0100000', '0000']),
  'ADCI' : (ra_rb_im, ['0100000', '01']),
  'ADCIM' : (ra_rb_im, ['0100010', '01']),
  'ADCM' : (ra_rb_rc, ['0100010', '0000']),
  'ADF' : (ra_rb_rc, ['0000001', '0000']),
  'ADFM' : (ra_rb_rc, ['0000011', '0000']),
  'ADI' : (ra_rb_im, ['0000000', '01']),
  'ADIM' : (ra_rb_im, ['0000010', '01']),
  'ADM' : (ra_rb_rc, ['0000010', '0000']),
  'AN' : (ra_rb_rc, ['0010100', '0000']),
  'ANI' : (ra_rb_im, ['0010100', '01']),
  'ANM' : (ra_rb_rc, ['0010110', '0000']),
  'B' : (co, ['110000']),
  'BF' : (ra_rb_lo_op, ['101001100', '1000000']),
  'BFM' : (ra_rb_lo_op, ['101001110', '1000000']),
  'BR' : (co_ra, ['110010',"000"]),
  'BRA' : (lo, ['111000100']),
  'BRR' : (lo, ['111000000']),
  'C' : (co, ['110101']),
  'CAA' : (lo, ['111001100']),
  'CAR' : (lo, ['111001000']),
  'CM' : (ra_rb_sh_ve, ['10111000']),
  'CMF' : (ra_rb_sh_ve, ['10111010']),
  'CMFM' : (ra_rb_sh_ve, ['10111110']),
  'CMI' : (ra_im, ['10111001']),
  'CMIM' : (ra_im, ['10111101']),
  'CMM' : (ra_rb_sh_ve, ['10111100']),
  'CR' : (co_ra, ['110111', '000']),
  'DBRK' : (no_re, ['111111111111111111']),
  'DI' : (ra_no_fl, ['101000000101', '0']),
  'DMT' : (ra_rb_rc, ['0110100', '00000']),
  'DV' : (ra_rb_rc, ['0001100', '0000']),
  'DVF' : (ra_rb_rc, ['0001101', '0000']),
  'DVFM' : (ra_rb_rc, ['0001111', '0000']),
  'DVI' : (ra_rb_im, ['0001100', '01']),
  'DVIM' : (ra_rb_im, ['0001110', '01']),
  'DVIS' : (ra_rb_im, ['0001100', '11']),
  'DVISM' : (ra_rb_im, ['0001110', '11']),
  'DVM' : (ra_rb_rc, ['0001110', '0000']),
  'DVS' : (ra_rb_rc, ['0001100', '0010']),
  'DVSM' : (ra_rb_rc, ['0001110', '0010']),
  'EI' : (ra_no_fl, ['101000000100', '0']),
  'FTI' : (ra_rb_lo_ve_no_fl, ['101000101', '00000000']),
  'FTIM' : (ra_rb_lo_ve_no_fl, ['101000111', '00000000']),
  'HT' : (no_re, ['101000000011000000']),
  'IR' : (no_re, ['101000000001000000']),
  'ITF' : (ra_rb_lo_ve_no_fl, ['101000100', '00000000']),
  'ITFM' : (ra_rb_lo_ve_no_fl, ['101000110', '00000000']),
  'LDS' : (ra_rb_of_re, ['1010100', '000']),
  'LDT' : (ra_rb_of_re, ['1010110', '000']),
  'LDW' : (ra_rb_of_re, ['1010101', '000']),
  'MD' : (ra_rb_rc, ['0010000', '0000']),
  'MDF' : (ra_rb_rc, ['0010001', '0000']),
  'MDFM' : (ra_rb_rc, ['0010011', '0000']),
  'MDI' : (ra_rb_im, ['0010000', '10']),
  'MDIM' : (ra_rb_im, ['0010010', '01']),
  'MDIS' : (ra_rb_im, ['0010000', '11']),
  'MDISM' : (ra_rb_im, ['0010010', '11']),
  'MDM' : (ra_rb_rc, ['0010010', '0000']),
  'MDS' : (ra_rb_rc, ['0010000', '0010']),
  'MDSM' : (ra_rb_rc, ['0010010', '0010']),
  'MH' : (ra_im_al, ['10001']),
  'ML' : (ra_im_al, ['10010']),
  'MS' : (ra_im_al, ['10011']),
  'MU' : (ra_rb_rc, ['0001000', '0000']),
  'MUF' : (ra_rb_rc, ['0001001', '0000']),
  'MUFM' : (ra_rb_rc, ['0001011', '0000']),
  'MUI' : (ra_rb_im, ['0001000', '01']),
  'MUIM' : (ra_rb_im, ['0001010', '01']),
  'MUIS' : (ra_rb_im, ['0001000', '11']),
  'MUISM' : (ra_rb_im, ['0001010', '11']),
  'MUM' : (ra_rb_rc, ['0001010', '0000']),
  'MUS' : (ra_rb_rc, ['0001000', '0010']),
  'MUSM' : (ra_rb_rc, ['0001010', '0010']),
  'NG' : (ra_rb_lo_op, ['101001100', '0000000']),
  'NGF' : (ra_rb_lo_op, ['101001101', '0000000']),
  'NGFM' : (ra_rb_lo_op, ['101001111', '0000000']),
  'NGM' : (ra_rb_lo_op, ['101001110', '0000000']),
  'NT' : (ra_rb_lo_op, ['101001100', '0100000']),
  'NTM' : (ra_rb_lo_op, ['101001110', '0100000']),
  'OR' : (ra_rb_rc, ['0011000', '0000']),
  'ORI' : (ra_rb_im, ['0011000', '01']),
  'ORM' : (ra_rb_rc, ['0011010', '0000']),
  'RE' : (no_re, ['101000000000000000']),
  'RF' : (ra_no_fl, ['101000001100', '0']),
  'RL' : (ra_rb_rc, ['0110000', '0000']),
  'RLI' : (ra_rb_im, ['1000000', '00']),
  'RLIM' : (ra_rb_im, ['1000010', '00']),
  'RLM' : (ra_rb_rc, ['0110010', '0000']),
  'RMP' : (ra_rb_lo_ve_no_fl_al, ['1010010', '0000000000']),
  'RND' : (ra_wi_fl, ['101001100', '000001100000']),
  'RNDM' : (ra_wi_fl, ['101001110', '000001100000']),
  'RR' : (ra_rb_rc, ['0110001', '0000']),
  'RRI' : (ra_rb_im, ['1000001', '00']),
  'RRIM' : (ra_rb_im, ['1000011', '00']),
  'RRM' : (ra_rb_rc, ['0110011', '0000']),
  'SA' : (ra_rb_rc, ['0101101', '0000']),
  'SAI' : (ra_rb_im, ['0111101', '00']),
  'SAIM' : (ra_rb_im, ['0111111', '00']),
  'SAM' : (ra_rb_rc, ['0101111', '0000']),
  'SB' : (ra_rb_rc, ['0000100', '0000']),
  'SBC' : (ra_rb_rc, ['0100100', '0000']),
  'SBCI' : (ra_rb_im, ['0100100', '01']),
  'SBCIM' : (ra_rb_im, ['0100110', '01']),
  'SBCM' : (ra_rb_rc, ['0100110', '0000']),
  'SBF' : (ra_rb_rc, ['0000101', '0000']),
  'SBFM' : (ra_rb_rc, ['0000111', '0000']),
  'SBI' : (ra_rb_im, ['0000100', '01']),
  'SBIM' : (ra_rb_im, ['0000110', '01']),
  'SBM' : (ra_rb_rc, ['0000110', '0000']),
  'SES' : (ra_rb_lo_ve_no_fl_al, ['101000000111', '00000']),
  'SEW' : (ra_rb_lo_ve_no_fl_al, ['1010000010000', '00000']),
  'SF' : (ra_no_fl, ['101000001011', '0']),
  'SL' : (ra_rb_rc, ['0101000', '0000']),
  'SLI' : (ra_rb_im, ['0111000', '00']),
  'SLIM' : (ra_rb_im, ['0111010', '00']),
  'SLM' : (ra_rb_rc, ['0101010', '0000']),
  'SMP' : (ra_rb_me, ['1010010', '1', '0000000']),
  'SR' : (ra_rb_rc, ['0101001', '0000']),
  'SRI' : (ra_rb_im, ['0111001', '00']),
  'SRIM' : (ra_rb_im, ['0111011', '00']),
  'SRM' : (ra_rb_rc, ['0101011', '0000']),
  'STS' : (ra_rb_of_re, ['1011000', '00']),
  'STT' : (ra_rb_of_re, ['1011010', '000']),
  'STW' : (ra_rb_of_re, ['1011001', '000']),
  'WT' : (no_re, ['101000000010000000']),
  'XR' : (ra_rb_rc, ['0011100', '0000']),
  'XRI' : (ra_rb_im, ['0011100', '01']),
  'XRM' : (ra_rb_rc, ['0011110', '0000']),
  'ZES' : (ra_rb_lo_ve_no_fl_al, ['101000001001', '00000']),
  'ZEW' : (ra_rb_lo_ve_no_fl_al, ['101000001010', '00000']),
}

REGISTER_MODE = 0
IMMEDIATE_MODE = 1

COND_NAMES = [
  "n", "e", "l", "le", "g", "ge", "no", "o", "ns", "s", "sl", "sle", "sg", "sge", None, ""
]

REGISTER_NAMES = [
    'r0',
    'r1',
    'r2',
    'r3',
    'r4',
    'r5',
    'r6',
    'r7',
    'r8',
    'r9',
    'r10',
    'r11',
    'r12',
    'r13',
    'r14',
    'r15',
    'r16',
    'r17',
    'r18',
    'r19',
    'r20',
    'r21',
    'r22',
    'r23',
    'r24',
    'r25',
    'r26',
    'r27',
    'r28',
    'st',
    'ra',
    'pc'
]

class CLEM():
    name = 'clem'
    address_size = 4
    default_int_size = 3

    regs = {
        'r0': RegisterInfo('r0', 4),
        'r1': RegisterInfo('r1', 4),
        'r2': RegisterInfo('r2', 4),
        'r3': RegisterInfo('r3', 4),
        'r4': RegisterInfo('r4', 4),
        'r5': RegisterInfo('r5', 4),
        'r6': RegisterInfo('r6', 4),
        'r7': RegisterInfo('r7', 4),
        'r8': RegisterInfo('r8', 4),
        'r9': RegisterInfo('r9', 4),
        'r10': RegisterInfo('r10', 4),
        'r11': RegisterInfo('r11', 4),
        'r12': RegisterInfo('r12', 4),
        'r13': RegisterInfo('r13', 4),
        'r14': RegisterInfo('r14', 4),
        'r15': RegisterInfo('r15', 4),
        'r16': RegisterInfo('r16', 4),
        'r17': RegisterInfo('r17', 4),
        'r18': RegisterInfo('r18', 4),
        'r19': RegisterInfo('r19', 4),
        'r20': RegisterInfo('r20', 4),
        'r21': RegisterInfo('r21', 4),
        'r22': RegisterInfo('r22', 4),
        'r23': RegisterInfo('r23', 4),
        'r24': RegisterInfo('r24', 4),
        'r25': RegisterInfo('r25', 4),
        'r26': RegisterInfo('r26', 4),
        'r27': RegisterInfo('r27', 4),
        'r28': RegisterInfo('r28', 4),
        'st': RegisterInfo('st', 4),
        'ra': RegisterInfo('ra', 4),
        'pc': RegisterInfo('pc', 4),
    }

    flags = ['s', 'o', 'c', 'z']

    # The first flag write type is ignored currently.
    # See: https://github.com/Vector35/binaryninja-api/issues/513
    flag_write_types = ['', '*']

    flags_written_by_flag_write_type = {
        '*': ['s', 'o', 'c', 'z'],
    }
    flag_roles = {
        's': FlagRole.NegativeSignFlagRole,
        'o': FlagRole.OverflowFlagRole,
        'c': FlagRole.CarryFlagRole,
        'z': FlagRole.ZeroFlagRole,
    }

    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_UGE: ['c', 'z'],
        LowLevelILFlagCondition.LLFC_ULT: ['c'],
        LowLevelILFlagCondition.LLFC_SGE: ['s', 'o', 'z'],
        LowLevelILFlagCondition.LLFC_SLT: ['s', 'o'],
        LowLevelILFlagCondition.LLFC_E: ['z'],
        LowLevelILFlagCondition.LLFC_NE: ['z'],
        LowLevelILFlagCondition.LLFC_NEG: ['s'],
        LowLevelILFlagCondition.LLFC_POS: ['s']
    }

    stack_pointer = 'st'

    def find_instruction(self, addr):
        '''
      found = []
      bytes_per_size = {}
      for name, (inst_type, values) in Instructions.items():
        size = inst_type.SIZE
        if size not in bytes_per_size:
          bytes_per_size[size] = read_memory_value(addr, size)

        inst = inst_type.decode(inst_type, name, values, addr, bytes_per_size[size])
        if inst != None:
          found.append(inst)
      if len(found) > 1:
        raise RuntimeError("Multiple instructions found {}".format([x.__class__.__name__ for x in found]))
      elif len(found) == 0:
        return None
      return found[0]
        '''
        found = []
        for mnem, (size, inst_type, values) in Instructions.items():
            if size not in bytes_per_size:
                bytes_per_size[size] = read_memory_value(bytez[off:off+size])

            parser = p_map.items(inst_type)
            inst = parser.decode(parser, mnem, values, va, bytes_per_size[size])
            if inst != None:
                found.append(inst)

        if len(found) > 1:
            raise RuntimeError("Multiple instructions found {}".format([x.__class__.__name__ for x in found]))
        elif len(found) == 0:
            return None
        found[0]

    def decode_instruction(self, data, addr):
        if len(data) < 4:
            return None

        instr = self.find_instruction(addr)
        if instr == None:
            log_error('[{:x}] Bad opcode'.format(addr))
            return None
        return instr

    def perform_get_instruction_info(self, data, addr):
        instr = self.decode_instruction(data, addr)
        if instr is None:
            return None

        result = InstructionInfo()
        result.length = instr.SIZE
        branch = instr.add_branches(result)

        return result

    def perform_get_instruction_text(self, data, addr):
        instr = self.decode_instruction(data, addr)
        if instr is None:
            return None

        tokens = []

        instruction_text = instr.get_name()
        if instr.conditional_sets_flags():
            instruction_text += '.'

        tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, '{:7s}'.format(instruction_text))
        ]
        operand_tokens = instr.get_operand_tokens()
        for i in range(len(operand_tokens)):
          tokens.append(operand_tokens[i])
          if i != len(operand_tokens) - 1:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ', '))

        return tokens, instr.SIZE

    def perform_get_instruction_low_level_il(self, data, addr, il):
      return None

class DefaultCallingConvention(CallingConvention):
    name = 'default'
    int_arg_regs = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8']
    int_return_reg = 'r0'

