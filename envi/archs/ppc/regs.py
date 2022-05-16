
"""
Home of the PowerPC module's register specs/code.
"""
import envi.registers as e_reg

gprs32 = [('r%s' % x, 32)  for x in range(32)]
gprs64 = [('r%s' % x, 64)  for x in range(32)]
floats = [('f%s' % x, 64)  for x in range(32)]
floats.append( ('FPSCR', 64) )
vectors = [('vr%s' % x, 128)  for x in range(64)]
vectors.append( ('VSCR', 32) )

sysregs = (
        ('acc', 64),
        ('cr', 64),
        ('msr', 64),
        ('ten', 64),
        ('SPEFSCR', 64),
        ('pc', 64),
        )

ppc_regs32 = []
ppc_regs = ppc_regs64 = []

ppc_regs64.extend(gprs64)
ppc_regs32.extend(gprs32)

REG_OFFSET_SYSREGS = len(ppc_regs)
ppc_regs64.extend(sysregs)
ppc_regs32.extend(sysregs)

REG_OFFSET_FLOAT = len(ppc_regs)
ppc_regs64.extend(floats)
ppc_regs32.extend(floats)

REG_OFFSET_VECTOR = len(ppc_regs)
ppc_regs64.extend(vectors)
ppc_regs32.extend(vectors)

from . import spr
# populate spr_regs from the PPC SPR register list (in spr.py)
spr_regs = [(str(x), 64) for x in range(1024)]
for sprnum, (rname, rdesc, bitsz) in spr.sprs.items():
    spr_regs[sprnum] = (rname, bitsz)

sprnames = {x:y.lower() for x,(y,z,b) in spr.sprs.items()}

REG_OFFSET_SPR = len(ppc_regs)
ppc_regs64.extend(spr_regs)
ppc_regs32.extend(spr_regs)

# sparse definition of TMR regs, so we fill in the gaps a bit
tmr_regs = [("TMRREG%d" % x, 64) for x in range(192) ]
tmr_regs[16] = ('tmcfg0', 64)

tpri_regs = [('tpri%d' % x, 64) for x in range(32)]
imsr_regs = [('imsr%d' % x, 64) for x in range(32)]
inia_regs = [('inia%d' % x, 64) for x in range(32)]
tmr_regs.extend(tpri_regs)
tmr_regs.extend([("TPRIREG%d" % x, 64) for x in range(224, 288) ])   # padding
tmr_regs.extend(imsr_regs)
tmr_regs.extend(inia_regs)

REG_OFFSET_TMR = len(ppc_regs)
ppc_regs64.extend(tmr_regs)
ppc_regs32.extend(tmr_regs)


REG_OFFSET_DCR = len(ppc_regs)
ppc_regs64.extend([('dcr%d' % x, 64) for x in range(1024)])
ppc_regs32.extend([('dcr%d' % x, 64) for x in range(1024)])


pmr_regs = []
pmr_regs.extend([('upmc%d' % x, 32) for x in range(16)])
pmr_regs.extend([('pmc%d' % x, 32) for x in range(16)])
pmr_regs.extend([('foo%d' % x, 32) for x in range(96)])
pmr_regs.extend([('upmlca%d' % x, 32) for x in range(16)])
pmr_regs.extend([('pmlca%d' % x, 32) for x in range(16)])
pmr_regs.extend([('bar%d' % x, 32) for x in range(96)])
pmr_regs.extend([('upmlcb%d' % x, 32) for x in range(16)])
pmr_regs.extend([('pmlcb%d' % x, 32) for x in range(16)])
pmr_regs.extend([('baz%d' % x, 32) for x in range(96)])
pmr_regs.append(('upmgc0', 64))
pmr_regs.extend([('fuq%d' % x, 32) for x in range(15)])
pmr_regs.append(('pmgc0', 64))

REG_OFFSET_PMR = len(ppc_regs)
ppc_regs64.extend(pmr_regs)
ppc_regs32.extend(pmr_regs)

#REG_OFFSET_TBR = len(ppc_regs)
REG_OFFSET_TBR = REG_OFFSET_SPR

# dynamically create REG_EAX and the like in our module
l = locals()
e_reg.addLocalEnums(l, ppc_regs)

# in order to make numbers work out the same, we translate bits differently from the manual
# the PPC Arch Ref Manual indicates the lower bits as 32-63.
ppc_meta32 = [
        ('SP', REG_R1, 0, 32),
        ('TOC', REG_R2, 0, 32),
        ('cr0', REG_CR, 63-35, 4),
        ('cr1', REG_CR, 63-39, 4),
        ('cr2', REG_CR, 63-43, 4),
        ('cr3', REG_CR, 63-47, 4),
        ('cr4', REG_CR, 63-51, 4),
        ('cr5', REG_CR, 63-55, 4),
        ('cr6', REG_CR, 63-59, 4),
        ('cr7', REG_CR, 63-63, 4),
        ('SO',  REG_XER, 63-32, 1),
        ('OV',  REG_XER, 63-33, 1),
        ('CA',  REG_XER, 63-34, 1),
        ('SOVH', REG_SPEFSCR, 63-32, 1,),
        ('OVH',  REG_SPEFSCR, 63-33, 1,),
        ('FGH',  REG_SPEFSCR, 63-34, 1,),
        ('FXH',  REG_SPEFSCR, 63-35, 1,),
        ('FINVH',REG_SPEFSCR, 63-36, 1,),
        ('FDBZH',REG_SPEFSCR, 63-37, 1,),
        ('FUNFH',REG_SPEFSCR, 63-38, 1,),
        ('FOVFH',REG_SPEFSCR, 63-39, 1,),
        ('FINXS',REG_SPEFSCR, 63-42, 1,),
        ('FINVS',REG_SPEFSCR, 63-43, 1,),
        ('FDBZS',REG_SPEFSCR, 63-44, 1,),
        ('FUNFS',REG_SPEFSCR, 63-45, 1,),
        ('FOVFS',REG_SPEFSCR, 63-46, 1,),
        ('SOV',  REG_SPEFSCR, 63-48, 1,),
        ('OV',   REG_SPEFSCR, 63-49, 1,),
        ('FG',   REG_SPEFSCR, 63-50, 1,),
        ('FX',   REG_SPEFSCR, 63-51, 1,),
        ('FINV', REG_SPEFSCR, 63-52, 1,),
        ('FDBZ', REG_SPEFSCR, 63-53, 1,),
        ('FUNF', REG_SPEFSCR, 63-54, 1,),
        ('FOVF', REG_SPEFSCR, 63-55, 1,),
        ('FINXE',REG_SPEFSCR, 63-57, 1,),
        ('FINVE',REG_SPEFSCR, 63-58, 1,),
        ('FDBZE',REG_SPEFSCR, 63-59, 1,),
        ('FUNFE',REG_SPEFSCR, 63-60, 1,),
        ('FOVFE',REG_SPEFSCR, 63-61, 1,),
        ('FRMC', REG_SPEFSCR, 63-62, 2,),

]
ppc_meta64 = [
        ('SP', REG_R1, 0, 64),
        ('TOC', REG_R2, 0, 64),
        ('cr0', REG_CR, 63-35, 4),
        ('cr1', REG_CR, 63-39, 4),
        ('cr2', REG_CR, 63-43, 4),
        ('cr3', REG_CR, 63-47, 4),
        ('cr4', REG_CR, 63-51, 4),
        ('cr5', REG_CR, 63-55, 4),
        ('cr6', REG_CR, 63-59, 4),
        ('cr7', REG_CR, 63-63, 4),
        ('SO',  REG_XER, 63-32, 1),
        ('OV',  REG_XER, 63-33, 1),
        ('CA',  REG_XER, 63-34, 1),
        ('SOVH', REG_SPEFSCR, 63-32, 1,),
        ('OVH',  REG_SPEFSCR, 63-33, 1,),
        ('FGH',  REG_SPEFSCR, 63-34, 1,),
        ('FXH',  REG_SPEFSCR, 63-35, 1,),
        ('FINVH',REG_SPEFSCR, 63-36, 1,),
        ('FDBZH',REG_SPEFSCR, 63-37, 1,),
        ('FUNFH',REG_SPEFSCR, 63-38, 1,),
        ('FOVFH',REG_SPEFSCR, 63-39, 1,),
        ('FINXS',REG_SPEFSCR, 63-42, 1,),
        ('FINVS',REG_SPEFSCR, 63-43, 1,),
        ('FDBZS',REG_SPEFSCR, 63-44, 1,),
        ('FUNFS',REG_SPEFSCR, 63-45, 1,),
        ('FOVFS',REG_SPEFSCR, 63-46, 1,),
        ('SOV',  REG_SPEFSCR, 63-48, 1,),
        ('OV',   REG_SPEFSCR, 63-49, 1,),
        ('FG',   REG_SPEFSCR, 63-50, 1,),
        ('FX',   REG_SPEFSCR, 63-51, 1,),
        ('FINV', REG_SPEFSCR, 63-52, 1,),
        ('FDBZ', REG_SPEFSCR, 63-53, 1,),
        ('FUNF', REG_SPEFSCR, 63-54, 1,),
        ('FOVF', REG_SPEFSCR, 63-55, 1,),
        ('FINXE',REG_SPEFSCR, 63-57, 1,),
        ('FINVE',REG_SPEFSCR, 63-58, 1,),
        ('FDBZE',REG_SPEFSCR, 63-59, 1,),
        ('FUNFE',REG_SPEFSCR, 63-60, 1,),
        ('FOVFE',REG_SPEFSCR, 63-61, 1,),
        ('FRMC', REG_SPEFSCR, 63-62, 2,),
]

vec_meta = [('v%d' % d, REG_OFFSET_VECTOR + d, 0, 128) for d in range(32)]
spe_meta = [('ev%d' % d, d, 0, 64) for d in range(32)]
spe_meta.extend([('ev%dh', d, 32, 32) for d in range(32)])   # upper half

ppc_meta32.extend(vec_meta)
ppc_meta64.extend(vec_meta)

ppc_meta32.extend(spe_meta)
ppc_meta64.extend(spe_meta)

statmetas = [
        ('CR0_LT', REG_CR, 63-32, 1, 'Less Than Flag'),
        ('CR0_GT', REG_CR, 63-33, 1, 'Greater Than Flag'),
        ('CR0_EQ', REG_CR, 63-34, 1, 'Equal to Flag'),
        ('CR0_SO', REG_CR, 63-35, 1, 'Summary Overflow Flag'),
        ('CR1_LT', REG_CR, 63-36, 1, 'Less Than Flag'),
        ('CR1_GT', REG_CR, 63-37, 1, 'Greater Than Flag'),
        ('CR1_EQ', REG_CR, 63-38, 1, 'Equal to Flag'),
        ('CR1_SO', REG_CR, 63-39, 1, 'Summary Overflow Flag'),
        ('CR2_LT', REG_CR, 63-40, 1, 'Less Than Flag'),
        ('CR2_GT', REG_CR, 63-41, 1, 'Greater Than Flag'),
        ('CR2_EQ', REG_CR, 63-42, 1, 'Equal to Flag'),
        ('CR2_SO', REG_CR, 63-43, 1, 'Summary Overflow Flag'),
        ('CR3_LT', REG_CR, 63-44, 1, 'Less Than Flag'),
        ('CR3_GT', REG_CR, 63-45, 1, 'Greater Than Flag'),
        ('CR3_EQ', REG_CR, 63-46, 1, 'Equal to Flag'),
        ('CR3_SO', REG_CR, 63-47, 1, 'Summary Overflow Flag'),
        ('CR4_LT', REG_CR, 63-48, 1, 'Less Than Flag'),
        ('CR4_GT', REG_CR, 63-49, 1, 'Greater Than Flag'),
        ('CR4_EQ', REG_CR, 63-50, 1, 'Equal to Flag'),
        ('CR4_SO', REG_CR, 63-51, 1, 'Summary Overflow Flag'),
        ('CR5_LT', REG_CR, 63-52, 1, 'Less Than Flag'),
        ('CR5_GT', REG_CR, 63-53, 1, 'Greater Than Flag'),
        ('CR5_EQ', REG_CR, 63-54, 1, 'Equal to Flag'),
        ('CR5_SO', REG_CR, 63-55, 1, 'Summary Overflow Flag'),
        ('CR6_LT', REG_CR, 63-56, 1, 'Less Than Flag'),
        ('CR6_GT', REG_CR, 63-57, 1, 'Greater Than Flag'),
        ('CR6_EQ', REG_CR, 63-58, 1, 'Equal to Flag'),
        ('CR6_SO', REG_CR, 63-59, 1, 'Summary Overflow Flag'),
        ('CR7_LT', REG_CR, 63-60, 1, 'Less Than Flag'),
        ('CR7_GT', REG_CR, 63-61, 1, 'Greater Than Flag'),
        ('CR7_EQ', REG_CR, 63-62, 1, 'Equal to Flag'),
        ('CR7_SO', REG_CR, 63-63, 1, 'Summary Overflow Flag'),

        ('SO',   REG_XER, 63-32, 1, 'Summary Overflow'),
        ('OV',   REG_XER, 63-33, 1, 'Overflow'),
        ('CA',   REG_XER, 63-34, 1, 'Carry'),

        ('FPSCR_FX',     REG_FPSCR, 63-32, 1, 'Floating-Point Exception Summary'),
        ('FPSCR_FEX',    REG_FPSCR, 63-33, 1, 'Floating-Point Enabled Exception Summary'),
        ('FPSCR_VX',     REG_FPSCR, 63-34, 1, 'Floating-Point Invalid Operation Exception Summary'),
        ('FPSCR_OX',     REG_FPSCR, 63-35, 1, 'Floating-Point Overflow Exception'),
        ('FPSCR_UX',     REG_FPSCR, 63-36, 1, 'Floating-Point Underflow Exception'),
        ('FPSCR_ZX',     REG_FPSCR, 63-37, 1, 'Floating-Point Zero Divide Exception'),
        ('FPSCR_XX',     REG_FPSCR, 63-38, 1, 'Floating-Point Inexact Exception'),
        ('FPSCR_VXSNAN', REG_FPSCR, 63-39, 1, 'Floating-Point Invalid Operation Exception (SNAN)'),
        ('FPSCR_VXISI',  REG_FPSCR, 63-40, 1, 'Floating-Point Invalid Operation Exception (∞ − ∞)'),
        ('FPSCR_VXIDI',  REG_FPSCR, 63-41, 1, 'Floating-Point Invalid Operation Exception (∞ ÷ ∞)'),
        ('FPSCR_VXZDZ',  REG_FPSCR, 63-42, 1, 'Floating-Point Invalid Operation Exception (0 ÷ 0)'),
        ('FPSCR_VXIMZ',  REG_FPSCR, 63-43, 1, 'Floating-Point Invalid Operation Exception (∞ × 0)'),
        ('FPSCR_VXVC',   REG_FPSCR, 63-44, 1, 'Floating-Point Invalid Operation Exception (invalid compare)'),
        ('FPSCR_FR',     REG_FPSCR, 63-45, 1, 'Floating-Point Fraction Rounded'),
        ('FPSCR_FI',     REG_FPSCR, 63-46, 1, 'Floating-Point Fraction Inexact'),
        ('FPSCR_FPRF',   REG_FPSCR, 63-46, 5, 'Floating-Point Results Flags'),
        ('FPSCR_C',      REG_FPSCR, 63-47, 1, 'Floating-Point Result Class Descriptor'),

        # The FPCC field is like the CRx fields, so we give them some special
        # names to make it easier to remember
        ('FPCC_FL',      REG_FPSCR, 63-48, 1, 'Floating-Point Less Than or Negative'),
        ('FPCC_FG',      REG_FPSCR, 63-49, 1, 'Floating-Point Greater Than or Positive'),
        ('FPCC_FE',      REG_FPSCR, 63-50, 1, 'Floating-Point Equal or Zero'),
        ('FPCC_FU',      REG_FPSCR, 63-51, 1, 'Floating-Point Unordered or NaN'),
        ('FPCC',         REG_FPSCR, 63-51, 4, 'Floating-Point Condition Code'),

        ('FPSCR_C_FPCC', REG_FPSCR, 63-51, 5, 'Floating-Point Result Class Descriptor and Condition Code'),
        ('FPSCR_VXSOFT', REG_FPSCR, 63-53, 1, 'Floating-Point Invalid Operation Exception (software request)'),
        ('FPSCR_VXSQRT', REG_FPSCR, 63-54, 1, 'Floating-Point Invalid Operation Exception (invalid square root)'),
        ('FPSCR_VXCVI',  REG_FPSCR, 63-55, 1, 'Floating-Point Invalid Operation Exception (invalid integer convert)'),
        ('FPSCR_VE',     REG_FPSCR, 63-56, 1, 'Floating-Point Invalid Operation Exception Enable'),
        ('FPSCR_OE',     REG_FPSCR, 63-57, 1, 'Floating-Point Overflow Exception Enable'),
        ('FPSCR_UE',     REG_FPSCR, 63-58, 1, 'Floating-Point Underflow Exception Enable'),
        ('FPSCR_ZE',     REG_FPSCR, 63-59, 1, 'Floating-Point Zero Divide Exception Enable'),
        ('FPSCR_XE',     REG_FPSCR, 63-60, 1, 'Floating-Point Inexact Exception Enable'),
        ('FPSCR_NI',     REG_FPSCR, 63-61, 1, 'Floating-Point non-IEEE Mode'),
        ('FPSCR_RN',     REG_FPSCR, 63-62, 2, 'Floating-Point Rounding Control'),

        ('MSR_CM',       REG_MSR, 63-32, 1, 'Computation Mode'),
        ('MSR_GS',       REG_MSR, 63-35, 1, 'Guest State'),
        ('MSR_UCLE',     REG_MSR, 63-37, 1, 'User-Mode Cache Lock Enable'),
        ('MSR_SPV',      REG_MSR, 63-38, 1, 'SP/Embedded Floating-Point/Vector Available'),
        ('MSR_WE',       REG_MSR, 63-45, 1, 'Wait State Enable'),
        ('MSR_CE',       REG_MSR, 63-46, 1, 'Critical Enable'),
        ('MSR_EE',       REG_MSR, 63-48, 1, 'External Enable'),
        ('MSR_PR',       REG_MSR, 63-49, 1, 'User Mode (problem State)'),
        ('MSR_FP',       REG_MSR, 63-50, 1, 'Floating-Point Available'),
        ('MSR_ME',       REG_MSR, 63-51, 1, 'Machine Check Enable'),
        ('MSR_FE0',      REG_MSR, 63-52, 1, 'Floating-Point Exception Mode 0'),
        ('MSR_DE',       REG_MSR, 63-54, 1, 'Debug Interrupt Enable'),
        ('MSR_FE1',      REG_MSR, 63-55, 1, 'Floating-Point Exception Mode 1'),
        ('MSR_IS',       REG_MSR, 63-58, 1, 'Instruction Address Space'),
        ('MSR_DS',       REG_MSR, 63-59, 1, 'Data Address Space'),
        ('MSR_PMM',      REG_MSR, 63-61, 1, 'Performance Monitor Mark'),
        ('MSR_RI',       REG_MSR, 63-62, 1, 'Recoverable Interrupt'),
        ('SPEFSCR_SOVH',  REG_SPEFSCR, 63-32, 1, 'Summary Integer Overflow High'),
        ('SPEFSCR_OVH',   REG_SPEFSCR, 63-33, 1, 'Integer Overflow High'),
        ('SPEFSCR_FGH',  REG_SPEFSCR, 63-34, 1, 'Embedded FP Guard Bit High'),
        ('SPEFSCR_FXH',  REG_SPEFSCR, 63-35, 1, 'Embedded floating-point inexact bit high'),
        ('SPEFSCR_FINVH',REG_SPEFSCR, 63-36, 1, 'Embedded floating-point invalid operation/input error high'),
        ('SPEFSCR_FDBZH',REG_SPEFSCR, 63-37, 1, 'Embedded floating-point divide by zero high'),
        ('SPEFSCR_FUNFH',REG_SPEFSCR, 63-38, 1, 'Embedded floating-point underflow high'),
        ('SPEFSCR_FOVFH',REG_SPEFSCR, 63-39, 1, 'Embedded floating-point overflow high'),
        ('SPEFSCR_FINXS',REG_SPEFSCR, 63-42, 1, 'Embedded floating-point inexact sticky flag'),
        ('SPEFSCR_FINVS',REG_SPEFSCR, 63-43, 1, 'Embedded floating-point invalid operation sticky flag'),
        ('SPEFSCR_FDBZS',REG_SPEFSCR, 63-44, 1, 'Embedded floating-point divide by zero sticky flag'),
        ('SPEFSCR_FUNFS',REG_SPEFSCR, 63-45, 1, 'Embedded floating-point underflow sticky flag'),
        ('SPEFSCR_FOVFS',REG_SPEFSCR, 63-46, 1, 'Embedded floating-point overflow sticky flag'),
        ('SPEFSCR_SOV',  REG_SPEFSCR, 63-48, 1, 'Summary integer overflow low'),
        ('SPEFSCR_OV',   REG_SPEFSCR, 63-49, 1, 'Integer overflow'),
        ('SPEFSCR_FG',   REG_SPEFSCR, 63-50, 1, 'Embedded floating-point guard bit (low/scalar)'),
        ('SPEFSCR_FX',   REG_SPEFSCR, 63-51, 1, 'Embedded floating-point inexact bit (low/scalar)'),
        ('SPEFSCR_FINV', REG_SPEFSCR, 63-52, 1, 'Embedded floating-point invalid operation/input error (low/scalar)'),
        ('SPEFSCR_FDBZ', REG_SPEFSCR, 63-53, 1, 'Embedded floating-point divide by zero (low/scalar)'),
        ('SPEFSCR_FUNF', REG_SPEFSCR, 63-54, 1, 'Embedded floating-point underflow (low/scalar)'),
        ('SPEFSCR_FOVF', REG_SPEFSCR, 63-55, 1, 'Embedded floating-point overflow (low/scalar)'),
        ('SPEFSCR_FINXE',REG_SPEFSCR, 63-57, 1, 'Embedded floating-point round (inexact) exception enable'),
        ('SPEFSCR_FINVE',REG_SPEFSCR, 63-58, 1, 'Embedded floating-point invalid operation/input error exception enable'),
        ('SPEFSCR_FDBZE',REG_SPEFSCR, 63-59, 1, 'Embedded floating-point divide by zero exception enable'),
        ('SPEFSCR_FUNFE',REG_SPEFSCR, 63-60, 1, 'Embedded floating-point underflow exception enable'),
        ('SPEFSCR_FOVFE',REG_SPEFSCR, 63-61, 1, 'Embedded floating-point overflow exception enable'),
        ('SPEFSCR_FRMC', REG_SPEFSCR, 63-62, 2, 'Embedded floating-point rounding mode control'),
]

def getCrFields(regval):
    ret = []
    for name,regval,shift,bits,desc in statmetas:
        ret.append( (name, regval >> shift & 1) )
    return ret

e_reg.addLocalStatusMetas(l, ppc_meta64, statmetas, 'EFLAGS')
e_reg.addLocalMetas(l, ppc_meta64)

class Ppc32RegisterContext(e_reg.RegisterContext):
    def __init__(self):
        e_reg.RegisterContext.__init__(self)
        self.loadRegDef(ppc_regs32)
        self.loadRegMetas(ppc_meta32, statmetas=statmetas)
        self.setRegisterIndexes(REG_PC, REG_SP, srindex=REG_CR)

class Ppc64RegisterContext(e_reg.RegisterContext):
    def __init__(self):
        e_reg.RegisterContext.__init__(self)
        self.loadRegDef(ppc_regs64)
        self.loadRegMetas(ppc_meta64, statmetas=statmetas)
        self.setRegisterIndexes(REG_PC, REG_SP, srindex=REG_CR)



regs_general = []
regs_general.extend([reg for reg, size in gprs64])
#regs_general.extend([reg for reg, size in floats])
#regs_general.extend([reg for reg, size in vectors])
regs_general.append('lr')
regs_general.append('xer')
regs_general.append('ctr')
regs_general.extend([reg for reg, size in sysregs])

regs_core = []
regs_core.extend([reg for reg, size in gprs64])
regs_core.append('pc')
regs_core.append('msr')
regs_core.append('cr')
regs_core.append('lr')
regs_core.append('ctr')
regs_core.append('xer')

regs_fpu = ['f%d' %x for x in range(32)]
regs_fpu.append('fpscr')

regs_altivec = ['vr%d' %x for x in range(64)]
regs_altivec.append('vscr')
regs_altivec.append('vrsave')

regs_spe = ['ev%dh' %x for x in range(32)]
regs_spe.append('acc')
regs_spe.append('spefscr')

regs_spr = [name for idx, (name, desc, bitsize) in spr.sprs.items()]


rctx32 = Ppc32RegisterContext()
rctx64 = Ppc64RegisterContext()


