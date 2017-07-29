
from const import *
import envi.registers as e_reg

'''
Strategy:
    * Use only distinct register for Register Context (unique in each bank)
    * Store a lookup table for the different banks of registers, based on the 
        register data in proc_modes (see const.py)
    * Emulator does translation from register/mode to actual storage container
        using reg_table and some math (see _getRegIdx)
'''
clm_regs = (
    ('r0', 27),
    ('r1', 27),
    ('r2', 27),
    ('r3', 27),
    ('r4', 27),
    ('r5', 27),
    ('r6', 27),
    ('r7', 27),
    ('r8', 27),
    ('r9', 27),
    ('r10', 27),
    ('r11', 27),
    ('r12', 27),
    ('r13', 27),
    ('r14', 27),
    ('r15', 27),
    ('r16', 27),
    ('r17', 27),
    ('r18', 27),
    ('r19', 27),
    ('r20', 27),
    ('r21', 27),
    ('r22', 27),
    ('r23', 27),
    ('r24', 27),
    ('r25', 27),
    ('r26', 27),
    ('r27', 27),
    ('r28', 27),
    ('st', 27),
    ('ra', 27),
    ('pc', 27),
    ('fl', 27),
)
MAX_REGS = 33

# done with banked register translation table

l = locals()
e_reg.addLocalEnums(l, clm_regs)

FL_Z = 0
FL_C = 1
FL_O = 2
FL_S = 3
FL_T1IE = 4
FL_T2IE = 5
FL_T3IE = 6
FL_T4IE = 7
FL_IIEE = 8
FL_D0EE = 9
FL_MEMEE = 10
FL_DRIE = 11
FL_DSIE = 12

fl_fields = [None for x in range(13)]
clm_status_metas = []
for k,v in globals().items():
    if k.startswith("FL_"):
        bit = 1<<v
        globals()[k+"_bit"] = bit
        globals()[k+"_mask"] = 0xffffffff & bit
        fl_fields[v] = k

        clm_status_metas.append( (k[3:], REG_FL, v, 1, '') )

clm_metas = [
        ("R13", REG_ST, 0, 27),
        ("R14", REG_RA, 0, 27),
        ("R15", REG_PC, 0, 27),
        ]

e_reg.addLocalStatusMetas(l, clm_metas, clm_status_metas, "CPSC")
e_reg.addLocalMetas(l, clm_metas)


class ClmRegisterContext(e_reg.RegisterContext):
    def __init__(self):
        e_reg.RegisterContext.__init__(self)
        self.loadRegDef(clm_regs)
        self.loadRegMetas(clm_metas, statmetas=clm_status_metas)
        self.setRegisterIndexes(REG_PC, REG_ST)

