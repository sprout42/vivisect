MODE_ARM        = 0
MODE_THUMB      = 1
MODE_JAZELLE    = 2
MODE_THUMBEE    = 3


#Support for different ARM Instruction set versions

# name          bitmask                    decimal         hex
REV_ARMv4   =   0b0000000000000000000001 #        1        0x1
REV_ARMv4T  =   0b0000000000000000000010 #        2        0x2
REV_ARMv5   =   0b0000000000000000000100 #        4        0x4
REV_ARMv5T  =   0b0000000000000000001000 #        8        0x8
REV_ARMv5E  =   0b0000000000000000010000 #       16        0x10
REV_ARMv5J  =   0b0000000000000000100000 #       32        0x20
REV_ARMv5TE =   0b0000000000000001000000 #       64        0x40
REV_ARMv6   =   0b0000000000000010000000 #      128        0x80
REV_ARMv6M  =   0b0000000000000100000000 #      256        0x100
REV_ARMv6T2 =   0b0000000000001000000000 #      512        0x200
REV_ARMv7A  =   0b0000000000010000000000 #     1024        0x400
REV_ARMv7R  =   0b0000000000100000000000 #     2048        0x800
REV_ARMv7M  =   0b0000000001000000000000 #     4096        0x1000
REV_ARMv7EM =   0b0000000010000000000000 #     8192        0x2000
REV_ARMv8A  =   0b0000000100000000000000 #    16384        0x4000
REV_ARMv8R  =   0b0000001000000000000000 #    32768        0x8000
REV_ARMv8M  =   0b0000010000000000000000 #    65536        0x10000

REV_ALL_ARMv4  = (REV_ARMv4 | REV_ARMv4T)
REV_ALL_ARMv5  = (REV_ARMv5 | REV_ARMv5T | REV_ARMv5E | REV_ARMv5J | REV_ARMv5TE)
REV_ALL_ARMv6  = (REV_ARMv6 | REV_ARMv6T2 | REV_ARMv6M)
REV_ALL_ARMv7  = (REV_ARMv7A | REV_ARMv7R | REV_ARMv7M | REV_ARMv7EM) 
REV_ALL_ARMv8  = (REV_ARMv8A | REV_ARMv8R | REV_ARMv8M)

#Todo - For easy instruction filtering add more like:
REV_ALL_TO_ARMv6 = REV_ALL_ARMv4 | REV_ALL_ARMv5 | REV_ALL_ARMv6
REV_ALL_FROM_ARMv6 = REV_ALL_ARMv6 | REV_ALL_ARMv7 | REV_ALL_ARMv8
#Note: since arm must be backwards compatible any depreciated commands
#Would be noted but not removed with the REV_ALL_TO_* if this is even used.
#These are put here for suggestion and comment for now

REV_ALL_ARM = (REV_ALL_ARMv4 | REV_ALL_ARMv5 | REV_ALL_ARMv6 | REV_ALL_ARMv7 | REV_ALL_ARMv8)

#Will be set below, THUMB16 up through v6 except v6T2, THUMB2 from v6T2 up, THUMBEE from v7 up.
REV_THUMB16 = REV_THUMB2  = REV_THUMBEE = 0   

ARCH_REVS = {}
#Itterate through all REV_ARM values and setup related combo values 
for name, val in globals().items():
    if (not name.startswith('REV_ARM')):
        continue
    shortName = name[4:]
    #add to lookup dictionary
    ARCH_REVS[shortName] = val
    #setup thumb versions to Architecture versions
    if (int(shortName[4]) > 6 or shortName == 'ARMv6T2'):
        REV_THUMB2 = REV_THUMB2 | val
        if int(shortName[4])!= 6:
            REV_THUMBEE = REV_THUMBEE | val
    else:
        REV_THUMB16 = REV_THUMB16 | val
#Added thumbs to dictionary
ARCH_REVS['thumb16'] = REV_THUMB16
ARCH_REVS['thumb'] = REV_THUMB2
ARCH_REVS['thumbee'] = REV_THUMBEE
ARCH_REVSLEN = len(ARCH_REVS)

# The supported types of operand shifts (by the 2 bit field)
S_LSL = 0
S_LSR = 1
S_ASR = 2
S_ROR = 3
S_RRX = 4 # FIXME HACK XXX add this

iencs = (\
    'IENC_DATA_SIMD',
    'IENC_LS_EXCL',
    'IENC_LS_NAPAIR_OFFSET',
    'IENC_LS_REGPAIR_POSTI',
    'IENC_LS_REGPAIR_OFFSET',
    'IENC_LS_REGPAIR_PREI',
    'IENC_LOG_SHFT_REG',
    'IENC_ADDSUB_SHFT_REG',
    'IENC_ADDSUB_EXT_REG',
    'IENC_SIMD_LS_MULTISTRUCT',
    'IENC_SIMD_LS_MULTISTRUCT_POSTI',
    'IENC_SIMD_LS_ONESTRUCT',
    'IENC_SIMD_LS_ONESTRUCT_POSTI',
    'IENC_PC_ADDR',
    'IENC_ADDSUB_IMM',
    'IENC_LOG_IMM',
    'IENC_MOV_WIDE_IMM',
    'IENC_BITFIELD',
    'IENC_EXTRACT',
    'IENC_CMP_BRANCH_IMM',
    'IENC_BRANCH_UNCOND_IMM',
    'IENC_BRANCH_COND_IMM',
    'IENC_EXCP_GEN',
    'IENC_SYS',
    'IENC_TEST_BRANCH_IMM',
    'IENC_BRANCH_UNCOND_REG',
    'IENC_LOAD_REG_LIT',
    'IENC_LS_REG_US_IMM',
    'IENC_LS_REG_UNSC_IMM',
    'IENC_LS_REG_UNPRIV',
    'IENC_LS_REG_IMM_PREI'
    'IENC_LS_REG_OFFSET',
    'IENC_ADDSUB_CARRY',
    'IENC_COND_CMP_REG',
    'IENC_COND_CMP_IMM',
    'IENC_COND_SEL',
    'IENC_DATA_PROC_3',
    'IENC_DATA_PROC_2',
    'IENC_DATA_PROC_1',
    'IENC_UNDEF'
)

IENC_MAX = len(iencs)

instrnames = [
    'ADR'
    'ADRP'
    'ADD'
    'ADDS'
    'SUB'
    'SUBS'
    'AND'
    'ORR'
    'EOR'
    'ANDS'
    'MOVN'
    'MOVZ'
    'MOVK'
    'SBFM'
    'BFM'
    'UBFM'
    'EXTR'
    'B'
    'BL'
    'SBC'
    'HVC'
    'SMC'
    'BRK'
    'HLT'
    'DCPS1'
    'DCPS2'
    'DCPS3'
    'MSRI'
    'HINT'
    'CLREX'
    'DSB'
    'DMB'
    'ISB'
    'SYS'
    'MSR'
    'SYSL'
    'MRS'
    'BR'
    'BLR'
    'RET'
    'ERET'
    'DRPS'
    'STXRB'
    'STLXRB'
    'LDXRB'
    'LDAXRB'
    'STLRB'
    'LDARB'
    'STXRH'
    'STLXRH'
    'LDXRH'
    'LDAXRH'
    'STLRH'
    'LDARH'
]

ins_index = 85
for instr in instrnames:
    globals()['INS_' + instr] = ins_index
    ins_index += 1


