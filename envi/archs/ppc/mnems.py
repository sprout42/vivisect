# -*- coding: latin-1 -*-

mnems = '''vaddubm
vmaxub
vrlb
vcmpequb
vmuloub
vaddfp
vmrghb
vpkuhum
vmhaddshs
vmhraddshs
vmladduhm
vmsumubm
vmsummbm
vmsumuhm
vmsumuhs
vmsumshm
vmsumshs
vsel
vperm
vsldoi
vmaddfp
vnmsubfp
vadduhm
vmaxuh
vrlh
vcmpequh
vmulouh
vsubfp
vmrghh
vpkuwum
vadduwm
vmaxuw
vrlw
vcmpequw
vmrghw
vpkuhus
vcmpeqfp
vpkuwus
vmaxsb
vslb
vmulosb
vrefp
vmrglb
vpkshus
vmaxsh
vslh
vmulosh
vrsqrtefp
vmrglh
vpkswus
vaddcuw
vmaxsw
vslw
vexptefp
vmrglw
vpkshss
vsl
vcmpgefp
vlogefp
vpkswss
evaddw
vaddubs
evaddiw
vminub
evsubfw
vsrb
evsubifw
vcmpgtub
evabs
vmuleub
evneg
evextsb
vrfin
evextsh
evrndw
vspltb
evcntlzw
evcntlsw
vupkhsb
brinc
evand
evandc
evxor
evor
evnor
eveqv
vorc
evnand
evsrwu
evsrws
evsrwiu
evsrwis
evslw
evslwi
evrlw
evsplati
evrlwi
evsplatfi
evmergehi
evmergelo
evmergehilo
evmergelohi
evcmpgtu
evcmpgts
evcmpltu
evcmplts
evcmpeq
vadduhs
vminuh
vsrh
vcmpgtuh
vmuleuh
vrfiz
vsplth
vupkhsh
evsel
evfsadd
vadduws
evfssub
vminuw
evfsabs
vsrw
evfsnabs
evfsneg
vcmpgtuw
evfsmul
evfsdiv
vrfip
evfscmpgt
vspltw
evfscmplt
evfscmpeq
vupklsb
evfscfui
evfscfsi
evfscfuf
evfscfsf
evfsctui
evfsctsi
evfsctuf
evfsctsf
evfsctuiz
evfsctsiz
evfststgt
evfststlt
evfststeq
efsadd
efssub
efsabs
vsr
efsnabs
efsneg
vcmpgtfp
efsmul
efsdiv
vrfim
efscmpgt
efscmplt
efscmpeq
vupklsh
efscfd
efscfui
efscfsi
efscfuf
efscfsf
efsctui
efsctsi
efsctuf
efsctsf
efsctuiz
efsctsiz
efststgt
efststlt
efststeq
efdadd
efdsub
efdabs
efdnabs
efdneg
efdmul
efddiv
efdcmpgt
efdcmplt
efdcmpeq
efdcfs
efdcfui
efdcfsi
efdcfuf
efdcfsf
efdctui
efdctsi
efdctuf
efdctsf
efdctuiz
efdctsiz
efdtstgt
efdtstlt
efdtsteq
evlddx
vaddsbs
evldd
evldwx
vminsb
evldw
evldhx
A-90
ERMnemonic
vsrab
evldh
vcmpgtsb
evlhhesplatx
vmulesb
evlhhesplat
vcfux
evlhhousplatx
vspltisb
evlhhousplat
evlhhossplatx
vpkpx
evlhhossplat
evlwhex
evlwhe
evlwhoux
evlwhou
evlwhosx
evlwhos
evlwwsplatx
evlwwsplat
evlwhsplatx
evlwhsplat
evstddx
evstdd
evstdwx
evstdw
evstdhx
evstdh
evstwhex
evstwhe
evstwhox
evstwho
evstwwex
evstwwe
evstwwox
evstwwo
vaddshs
vminsh
vsrah
vcmpgtsh
vmulesh
vcfsx
vspltish
vupkhpx
vaddsws
vminsw
vsraw
vcmpgtsw
vctuxs
vspltisw
vcmpbfp
vctsxs
vupklpx
vsububm
vavgub
evmhessf
vabsdub
vand
vcmpequb.
evmhossf
evmheumi
evmhesmi
vmaxfp
evmhesmf
evmhoumi
vslo
evmhosmi
evmhosmf
evmhessfa
A-92
ERMnemonic
evmhossfa
evmheumia
evmhesmia
evmhesmfa
evmhoumia
evmhosmia
evmhosmfa
vsubuhm
vavguh
vabsduh
vandc
vcmpequh.
evmwhssf
evmwlumi
vminfp
evmwhumi
vsro
evmwhsmi
evmwhsmf
evmwssf
evmwumi
evmwsmi
evmwsmf
evmwhssfa
evmwlumia
evmwhumia
evmwhsmia
evmwhsmfa
evmwssfa
evmwumia
evmwsmia
evmwsmfa
vsubuwm
vavguw
vabsduw
vor
vcmpequw.
evaddusiaaw
evaddssiaaw
evsubfusiaaw
evsubfssiaaw
evmra
vxor
evdivws
vcmpeqfp.
evdivwu
evaddumiaaw
evaddsmiaaw
evsubfumiaaw
evsubfsmiaaw
evmheusiaaw
evmhessiaaw
vavgsb
evmhessfaaw
evmhousiaaw
vnor
evmhossiaaw
evmhossfaaw
evmheumiaaw
evmhesmiaaw
evmhesmfaaw
evmhoumiaaw
evmhosmiaaw
evmhosmfaaw
evmhegumiaa
evmhegsmiaa
evmhegsmfaa
evmhogumiaa
evmhogsmiaa
evmhogsmfaa
A-94
ERMnemonic
evmwlusiaaw
evmwlssiaaw
vavgsh
evmwhssmaaw
evmwlumiaaw
evmwlsmiaaw
evmwssfaa
evmwumiaa
evmwsmiaa
evmwsmfaa
evmheusianw
vsubcuw
evmhessianw
vavgsw
evmhessfanw
evmhousianw
evmhossianw
evmhossfanw
evmheumianw
evmhesmianw
evmhesmfanw
evmhoumianw
evmhosmianw
evmhosmfanw
evmhegumian
evmhegsmian
evmhegsmfan
evmhogumian
evmhogsmian
evmhogsmfan
evmwlusianw
evmwlssianw
vcmpgefp.
evmwlumianw
evmwlsmianw
evmwssfan
evmwumian
evmwsmian
evmwsmfan
vsububs
mfvscr
vcmpgtub.
vsum4ubs
vsubuhs
mtvscr
vcmpgtuh.
vsum4shs
vsubuws
vcmpgtuw.
vsum2sws
vcmpgtfp.
vsubsbs
vcmpgtsb.
vsum4sbs
vsubshs
vcmpgtsh.
vsubsws
vcmpgtsw.
vsumsws
vcmpbfp.'''







encodings = '''tdi 0 0 0 0 1 0
 TO
 rA
 SIMM
 D
 64
twi 0 0 0 0 1 1
 TO
 rA
 SIMM
 D
vaddubm 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 0
 0
 0 0 0
 0
 0
 VX
 V
vmaxub 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 0
 0
 0 0 0
 1
 0
 VX
 V
vrlb 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 0
 0
 0 0 1
 0
 0
 VX
 V
vcmpequb 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 0
 0
 0 0 1
 1
 0
 VC
 V
vmuloub 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 0
 0
 0 1 0
 0
 0
 VX
 V
vaddfp 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 0
 0
 0 1 0
 1
 0
 VX
 V
vmrghb 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 0
 0
 0 1 1
 0
 0
 VX
 V
vpkuhum 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 0
 0
 0 1 1
 1
 0
 VX
 V
vmhaddshs 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 0 0
 0
 0
 VA
 V
vmhraddshs 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 0 0
 0
 1
 VA
 V
vmladduhm 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 0 0
 1
 0
 VA
 V
vmsumubm 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 0 1
 0
 0
 VA
 V
vmsummbm 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 0 1
 0
 1
 VA
 V
vmsumuhm 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 0 1
 1
 0
 VA
 V
vmsumuhs 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 0 1
 1
 1
 VA
 V
vmsumshm 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 1 0
 0
 0
 VA
 V
vmsumshs 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 1 0
 0
 1
 VA
 V
vsel 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 1 0
 1
 0
 VA
 V
vperm 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 1 0
 1
 1
 VA
 V
vsldoi 0 0 0 1 0 0
 vD
 vA
 vB
 /
 SH
 1
 0 1 1
 0
 0
 VX
 V
vmaddfp 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 1 1
 1
 0
 VA
 V
vnmsubfp 0 0 0 1 0 0
 vD
 vA
 vB
 vC
 1
 0 1 1
 1
 1
 VA
 V
vadduhm 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 1
 0
 0 0 0
 0
 0
 VX
 V
vmaxuh 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 1
 0
 0 0 0
 1
 0
 VX
 V
vrlh 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 1
 0
 0 0 1
 0
 0
 VX
 V
vcmpequh 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 1
 0
 0 0 1
 1
 0
 VC
 V
vmulouh 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 1
 0
 0 1 0
 0
 0
 VX
 V
vsubfp 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 1
 0
 0 1 0
 1
 0
 VX
 V
vmrghh 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 1
 0
 0 1 1
 0
 0
 VX
 V
vpkuwum 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 0 1
 0
 0 1 1
 1
 0
 VX
 V
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-85
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
vadduwm 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 1 0
 0
 0 0 0
 0
 0
 VX
 V
vmaxuw 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 1 0
 0
 0 0 0
 1
 0
 VX
 V
vrlw 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 1 0
 0
 0 0 1
 0
 0
 VX
 V
vcmpequw 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 1 0
 0
 0 0 1
 1
 0
 VC
 V
vmrghw 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 1 0
 0
 0 1 1
 0
 0
 VX
 V
vpkuhus 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 1 0
 0
 0 1 1
 1
 0
 VX
 V
vcmpeqfp 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 1 1
 0
 0 0 1
 1
 0
 VC
 V
vpkuwus 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 0 1 1
 0
 0 1 1
 1
 0
 VX
 V
vmaxsb 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 0 0
 0
 0 0 0
 1
 0
 VX
 V
vslb 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 0 0
 0
 0 0 1
 0
 0
 VX
 V
vmulosb 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 0 0
 0
 0 1 0
 0
 0
 VX
 V
vrefp 0 0 0 1 0 0
 vD
 ///
 vB
 0 0 1 0 0
 0
 0 1 0
 1
 0
 VX
 V
vmrglb 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 0 0
 0
 0 1 1
 0
 0
 VX
 V
vpkshus 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 0 0
 0
 0 1 1
 1
 0
 VX
 V
vmaxsh 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 0 1
 0
 0 0 0
 1
 0
 VX
 V
vslh 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 0 1
 0
 0 0 1
 0
 0
 VX
 V
vmulosh 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 0 1
 0
 0 1 0
 0
 0
 VX
 V
vrsqrtefp 0 0 0 1 0 0
 vD
 ///
 vB
 0 0 1 0 1
 0
 0 1 0
 1
 0
 VX
 V
vmrglh 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 0 1
 0
 0 1 1
 0
 0
 VX
 V
vpkswus 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 0 1
 0
 0 1 1
 1
 0
 VX
 V
vaddcuw 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 1 0
 0
 0 0 0
 0
 0
 VX
 V
vmaxsw 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 1 0
 0
 0 0 0
 1
 0
 VX
 V
vslw 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 1 0
 0
 0 0 1
 0
 0
 VX
 V
vexptefp 0 0 0 1 0 0
 vD
 ///
 vB
 0 0 1 1 0
 0
 0 1 0
 1
 0
 VX
 V
vmrglw 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 1 0
 0
 0 1 1
 0
 0
 VX
 V
vpkshss 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 1 0
 0
 0 1 1
 1
 0
 VX
 V
vsl 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 1 1
 0
 0 0 1
 0
 0
 VX
 V
vcmpgefp 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 1 1
 0
 0 0 1
 1
 0
 VC
 V
vlogefp 0 0 0 1 0 0
 vD
 ///
 vB
 0 0 1 1 1
 0
 0 1 0
 1
 0
 VX
 V
vpkswss 0 0 0 1 0 0
 vD
 vA
 vB
 0 0 1 1 1
 0
 0 1 1
 1
 0
 VX
 V
evaddw 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 0
 0 0 0
 0
 0
 EVX SP
vaddubs 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 0 0
 0
 0 0 0
 0
 0
 VX
 V
evaddiw 0 0 0 1 0 0
 rD
 UIMM
 rB
 0 1 0 0 0
 0
 0 0 0
 1
 0
 EVX SP
vminub 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 0 0
 0
 0 0 0
 1
 0
 VX
 V
evsubfw 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 0
 0 0 1
 0
 0
 EVX SP
A-86
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
vsrb 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 0 0
 0
 0 0 1
 0
 0
 VX
 V
evsubifw 0 0 0 1 0 0
 rD
 UIMM
 rB
 0 1 0 0 0
 0
 0 0 1
 1
 0
 EVX SP
vcmpgtub 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 0 0
 0
 0 0 1
 1
 0
 VC
 V
evabs 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 0 0
 0
 0 1 0
 0
 0
 EVX SP
vmuleub 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 0 0
 0
 0 1 0
 0
 0
 VX
 V
evneg 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 0 0
 0
 0 1 0
 0
 1
 EVX SP
evextsb 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 0 0
 0
 0 1 0
 1
 0
 EVX SP
vrfin 0 0 0 1 0 0
 vD
 ///
 vB
 0 1 0 0 0
 0
 0 1 0
 1
 0
 VX
 V
evextsh 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 0 0
 0
 0 1 0
 1
 1
 EVX SP
evrndw 0 0 0 1 0 0
 rD
 rA
 UIMM
 0 1 0 0 0
 0
 0 1 1
 0
 0
 EVX SP
vspltb 0 0 0 1 0 0
 vD
 UIMM
 vB
 0 1 0 0 0
 0
 0 1 1
 0
 0
 VX
 V
evcntlzw 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 0 0
 0
 0 1 1
 0
 1
 EVX SP
evcntlsw 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 0 0
 0
 0 1 1
 1
 0
 EVX SP
vupkhsb 0 0 0 1 0 0
 vD
 ///
 vB
 0 1 0 0 0
 0
 0 1 1
 1
 0
 VX
 V
brinc 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 0
 0 1 1
 1
 1
 EVX SP
evand 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 0
 1 0 0
 0
 1
 EVX SP
evandc 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 0
 1 0 0
 1
 0
 EVX SP
evxor 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 0
 1 0 1
 1
 0
 EVX SP
evor 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 0
 1 0 1
 1
 1
 EVX SP
evnor 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 0
 1 1 0
 0
 0
 EVX SP
eveqv 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 0
 1 1 0
 0
 1
 EVX SP
evorc 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 0
 1 1 0
 1
 1
 EVX SP
evnand 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 0
 1 1 1
 1
 0
 EVX SP
evsrwu 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 1
 0 0 0
 0
 0
 EVX SP
evsrws 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 1
 0 0 0
 0
 1
 EVX SP
evsrwiu 0 0 0 1 0 0
 rD
 rA
 UIMM
 0 1 0 0 0
 1
 0 0 0
 1
 0
 EVX SP
evsrwis 0 0 0 1 0 0
 rD
 rA
 UIMM
 0 1 0 0 0
 1
 0 0 0
 1
 1
 EVX SP
evslw 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 1
 0 0 1
 0
 0
 EVX SP
evslwi 0 0 0 1 0 0
 rD
 rA
 UIMM
 0 1 0 0 0
 1
 0 0 1
 1
 0
 EVX SP
evrlw 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 1
 0 1 0
 0
 0
 EVX SP
evsplati 0 0 0 1 0 0
 rD
 SIMM
 ///
 0 1 0 0 0
 1
 0 1 0
 0
 1
 EVX SP
evrlwi 0 0 0 1 0 0
 rD
 rA
 UIMM
 0 1 0 0 0
 1
 0 1 0
 1
 0
 EVX SP
evsplatfi 0 0 0 1 0 0
 rD
 SIMM
 ///
 0 1 0 0 0
 1
 0 1 0
 1
 1
 EVX SP
evmergehi 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 1
 0 1 1
 0
 0
 EVX SP
evmergelo 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 1
 0 1 1
 0
 1
 EVX SP
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-87
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
evmergehilo 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 1
 0 1 1
 1
 0
 EVX SP
evmergelohi 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 0
 1
 0 1 1
 1
 1
 EVX SP
evcmpgtu 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 0 0
 1
 1 0 0
 0
 0
 EVX SP
evcmpgts 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 0 0
 1
 1 0 0
 0
 1
 EVX SP
evcmpltu 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 0 0
 1
 1 0 0
 1
 0
 EVX SP
evcmplts 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 0 0
 1
 1 0 0
 1
 1
 EVX SP
evcmpeq 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 0 0
 1
 1 0 1
 0
 0
 EVX SP
vadduhs 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 0 1
 0
 0 0 0
 0
 0
 VX
 V
vminuh 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 0 1
 0
 0 0 0
 1
 0
 VX
 V
vsrh 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 0 1
 0
 0 0 1
 0
 0
 VX
 V
vcmpgtuh 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 0 1
 0
 0 0 1
 1
 0
 VC
 V
vmuleuh 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 0 1
 0
 0 1 0
 0
 0
 VX
 V
vrfiz 0 0 0 1 0 0
 vD
 ///
 vB
 0 1 0 0 1
 0
 0 1 0
 1
 0
 VX
 V
vsplth 0 0 0 1 0 0
 vD
 UIMM
 vB
 0 1 0 0 1
 0
 0 1 1
 0
 0
 VX
 V
vupkhsh 0 0 0 1 0 0
 vD
 ///
 vB
 0 1 0 0 1
 0
 0 1 1
 1
 0
 VX
 V
evsel 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 0 1
 1
 1 1
 crfS
 EVX SP
evfsadd 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 0
 0
 0 0 0
 0
 0
 EVX SP.FV
vadduws 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 1 0
 0
 0 0 0
 0
 0
 VX
 V
evfssub 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 0
 0
 0 0 0
 0
 1
 EVX SP.FV
vminuw 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 1 0
 0
 0 0 0
 1
 0
 VX
 V
evfsabs 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 1 0
 0
 0 0 1
 0
 0
 EVX SP.FV
vsrw 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 1 0
 0
 0 0 1
 0
 0
 VX
 V
evfsnabs 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 1 0
 0
 0 0 1
 0
 1
 EVX SP.FV
evfsneg 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 1 0
 0
 0 0 1
 1
 0
 EVX SP.FV
vcmpgtuw 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 1 0
 0
 0 0 1
 1
 0
 VC
 V
evfsmul 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 0
 0
 0 1 0
 0
 0
 EVX SP.FV
evfsdiv 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 0
 0
 0 1 0
 0
 1
 EVX SP.FV
vrfip 0 0 0 1 0 0
 vD
 ///
 vB
 0 1 0 1 0
 0
 0 1 0
 1
 0
 VX
 V
evfscmpgt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 0
 0
 0 1 1
 0
 0
 EVX SP.FV
vspltw 0 0 0 1 0 0
 vD
 UIMM
 vB
 0 1 0 1 0
 0
 0 1 1
 0
 0
 VX
 V
evfscmplt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 0
 0
 0 1 1
 0
 1
 EVX SP.FV
evfscmpeq 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 0
 0
 0 1 1
 1
 0
 EVX SP.FV
vupklsb 0 0 0 1 0 0
 vD
 ///
 vB
 0 1 0 1 0
 0
 0 1 1
 1
 0
 VX
 V
evfscfui 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 0
 0
 1 0 0
 0
 0
 EVX SP.FV
evfscfsi 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 0
 0
 1 0 0
 0
 1
 EVX SP.FV
A-88
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
evfscfuf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 0
 0
 1 0 0
 1
 0
 EVX SP.FV
evfscfsf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 0
 0
 1 0 0
 1
 1
 EVX SP.FV
evfsctui 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 0
 0
 1 0 1
 0
 0
 EVX SP.FV
evfsctsi 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 0
 0
 1 0 1
 0
 1
 EVX SP.FV
evfsctuf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 0
 0
 1 0 1
 1
 0
 EVX SP.FV
evfsctsf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 0
 0
 1 0 1
 1
 1
 EVX SP.FV
evfsctuiz 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 0
 0
 1 1 0
 0
 0
 EVX SP.FV
evfsctsiz 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 0
 0
 1 1 0
 1
 0
 EVX SP.FV
evfststgt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 0
 0
 1 1 1
 0
 0
 EVX SP.FV
evfststlt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 0
 0
 1 1 1
 0
 1
 EVX SP.FV
evfststeq 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 0
 0
 1 1 1
 1
 0
 EVX SP.FV
efsadd 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 1
 0
 0 0 0
 0
 0
 EVX SP.FS
efssub 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 1
 0
 0 0 0
 0
 1
 EVX SP.FS
efsabs 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 1 1
 0
 0 0 1
 0
 0
 EVX SP.FS
vsr 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 1 1
 0
 0 0 1
 0
 0
 VX
 V
efsnabs 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 1 1
 0
 0 0 1
 0
 1
 EVX SP.FS
efsneg 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 1 1
 0
 0 0 1
 1
 0
 EVX SP.FS
vcmpgtfp 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 0 1 1
 0
 0 0 1
 1
 0
 VC
 V
efsmul 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 1
 0
 0 1 0
 0
 0
 EVX SP.FS
efsdiv 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 1
 0
 0 1 0
 0
 1
 EVX SP.FS
vrfim 0 0 0 1 0 0
 vD
 ///
 vB
 0 1 0 1 1
 0
 0 1 0
 1
 0
 VX
 V
efscmpgt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 0
 0 1 1
 0
 0
 EVX SP.FS
efscmplt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 0
 0 1 1
 0
 1
 EVX SP.FS
efscmpeq 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 0
 0 1 1
 1
 0
 EVX SP.FS
vupklsh 0 0 0 1 0 0
 vD
 ///
 vB
 0 1 0 1 1
 0
 0 1 1
 1
 0
 VX
 V
efscfd 0 0 0 1 0 0
 rD
 0
 0 0 0 0
 rB
 0 1 0 1 1
 0
 0 1 1
 1
 1
 EVX SP.FS
efscfui 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 0
 1 0 0
 0
 0
 EVX SP.FS
efscfsi 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 0
 1 0 0
 0
 1
 EVX SP.FS
efscfuf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 0
 1 0 0
 1
 0
 EVX SP.FS
efscfsf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 0
 1 0 0
 1
 1
 EVX SP.FS
efsctui 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 0
 1 0 1
 0
 0
 EVX SP.FS
efsctsi 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 0
 1 0 1
 0
 1
 EVX SP.FS
efsctuf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 0
 1 0 1
 1
 0
 EVX SP.FS
efsctsf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 0
 1 0 1
 1
 1
 EVX SP.FS
efsctuiz 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 0
 1 1 0
 0
 0
 EVX SP.FS
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-89
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
efsctsiz 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 0
 1 1 0
 1
 0
 EVX SP.FS
efststgt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 0
 1 1 1
 0
 0
 EVX SP.FS
efststlt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 0
 1 1 1
 0
 1
 EVX SP.FS
efststeq 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 0
 1 1 1
 1
 0
 EVX SP.FS
efdadd 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 1
 1
 0 0 0
 0
 0
 EVX SP.FD
efdsub 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 1
 1
 0 0 0
 0
 1
 EVX SP.FD
efdabs 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 1 1
 1
 0 0 1
 0
 0
 EVX SP.FD
efdnabs 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 1 1
 1
 0 0 1
 0
 1
 EVX SP.FD
efdneg 0 0 0 1 0 0
 rD
 rA
 ///
 0 1 0 1 1
 1
 0 0 1
 1
 0
 EVX SP.FD
efdmul 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 1
 1
 0 1 0
 0
 0
 EVX SP.FD
efddiv 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 0 1 1
 1
 0 1 0
 0
 1
 EVX SP.FD
efdcmpgt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 1
 0 1 1
 0
 0
 EVX SP.FD
efdcmplt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 1
 0 1 1
 0
 1
 EVX SP.FD
efdcmpeq 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 1
 0 1 1
 1
 0
 EVX SP.FD
efdcfs 0 0 0 1 0 0
 rD
 0
 0 0 0 0
 rB
 0 1 0 1 1
 1
 0 1 1
 1
 1
 EVX SP.FD
efdcfui 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 1
 1 0 0
 0
 0
 EVX SP.FD
efdcfsi 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 1
 1 0 0
 0
 1
 EVX SP.FD
efdcfuf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 1
 1 0 0
 1
 0
 EVX SP.FD
efdcfsf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 1
 1 0 0
 1
 1
 EVX SP.FD
efdctui 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 1
 1 0 1
 0
 0
 EVX SP.FD
efdctsi 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 1
 1 0 1
 0
 1
 EVX SP.FD
efdctuf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 1
 1 0 1
 1
 0
 EVX SP.FD
efdctsf 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 1
 1 0 1
 1
 1
 EVX SP.FD
efdctuiz 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 1
 1 1 0
 0
 0
 EVX SP.FD
efdctsiz 0 0 0 1 0 0
 rD
 ///
 rB
 0 1 0 1 1
 1
 1 1 0
 1
 0
 EVX SP.FD
efdtstgt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 1
 1 1 1
 0
 0
 EVX SP.FD
efdtstlt 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 1
 1 1 1
 0
 1
 EVX SP.FD
efdtsteq 0 0 0 1 0 0
 crD
 /
 /
 rA
 rB
 0 1 0 1 1
 1
 1 1 1
 1
 0
 EVX SP.FD
evlddx 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 1 0 0
 0
 0 0 0
 0
 0
 EVX SP
vaddsbs 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 0 0
 0
 0 0 0
 0
 0
 VX
 V
1
evldd 0 0 0 1 0 0
 rD
 rA
 UIMM 0 1 1 0 0
 0
 0 0 0
 0
 1
 EVX SP
evldwx 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 1 0 0
 0
 0 0 0
 1
 0
 EVX SP
vminsb 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 0 0
 0
 0 0 0
 1
 0
 VX
 V
2
evldw 0 0 0 1 0 0
 rD
 rA
 UIMM
 0 1 1 0 0
 0
 0 0 0
 1
 1
 EVX SP
evldhx 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 1 0 0
 0
 0 0 1
 0
 0
 EVX SP
A-90
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
vsrab 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 0 0
 0
 0 0 1
 0
 0
 VX
 V
3
evldh 0 0 0 1 0 0
 rD
 rA
 UIMM 0 1 1 0 0
 0
 0 0 1
 0
 1
 EVX SP
vcmpgtsb 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 0 0
 0
 0 0 1
 1
 0
 VC
 V
evlhhesplatx 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 1 0 0
 0
 0 1 0
 0
 0
 EVX SP
vmulesb 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 0 0
 0
 0 1 0
 0
 0
 VX
 V
2
evlhhesplat 0 0 0 1 0 0
 rD
 rA
 UIMM 0 1 1 0 0
 0
 0 1 0
 0
 1
 EVX SP
vcfux 0 0 0 1 0 0
 vD
 UIMM
 vB
 0 1 1 0 0
 0
 0 1 0
 1
 0
 VX
 V
evlhhousplatx 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 1 0 0
 0
 0 1 1
 0
 0
 EVX SP
vspltisb 0 0 0 1 0 0
 vD
 SIMM
 ///
 0 1 1 0 0
 0
 0 1 1
 0
 0
 VX
 V
2
evlhhousplat 0 0 0 1 0 0
 rD
 rA
 UIMM
 0 1 1 0 0
 0
 0 1 1
 0
 1
 EVX SP
evlhhossplatx 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 1 0 0
 0
 0 1 1
 1
 0
 EVX SP
vpkpx 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 0 0
 0
 0 1 1
 1
 0
 VX
 V
evlhhossplat 0 0 0 1 0 0
 rD
 rA
 UIMM 2
 0 1 1 0 0
 0
 0 1 1
 1
 1
 EVX SP
evlwhex 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 1 0 0
 0
 1 0 0
 0
 0
 EVX SP
2
evlwhe 0 0 0 1 0 0
 rD
 rA
 UIMM 0 1 1 0 0
 0
 1 0 0
 0
 1
 EVX SP
evlwhoux 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 1 0 0
 0
 1 0 1
 0
 0
 EVX SP
evlwhou 0 0 0 1 0 0
 rD
 rA
 UIMM 2
 0 1 1 0 0
 0
 1 0 1
 0
 1
 EVX SP
evlwhosx 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 1 0 0
 0
 1 0 1
 1
 0
 EVX SP
2
evlwhos 0 0 0 1 0 0
 rD
 rA
 UIMM 0 1 1 0 0
 0
 1 0 1
 1
 1
 EVX SP
evlwwsplatx 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 1 0 0
 0
 1 1 0
 0
 0
 EVX SP
3
evlwwsplat 0 0 0 1 0 0
 rD
 rA
 UIMM
 0 1 1 0 0
 0
 1 1 0
 0
 1
 EVX SP
evlwhsplatx 0 0 0 1 0 0
 rD
 rA
 rB
 0 1 1 0 0
 0
 1 1 1
 0
 0
 EVX SP
2
evlwhsplat 0 0 0 1 0 0
 rD
 rA
 UIMM 0 1 1 0 0
 0
 1 1 1
 0
 1
 EVX SP
evstddx 0 0 0 1 0 0
 rS
 rA
 rB
 0 1 1 0 0
 1
 0 0 0
 0
 0
 EVX SP
evstdd 0 0 0 1 0 0
 rD
 rA
 UIMM 1
 0 1 1 0 0
 1
 0 0 0
 0
 1
 EVX SP
evstdwx 0 0 0 1 0 0
 rS
 rA
 rB
 0 1 1 0 0
 1
 0 0 0
 1
 0
 EVX SP
3
evstdw 0 0 0 1 0 0
 rS
 rA
 UIMM 0 1 1 0 0
 1
 0 0 0
 1
 1
 EVX SP
evstdhx 0 0 0 1 0 0
 rS
 rA
 rB
 0 1 1 0 0
 1
 0 0 1
 0
 0
 EVX SP
2
evstdh 0 0 0 1 0 0
 rS
 rA
 UIMM 0 1 1 0 0
 1
 0 0 1
 0
 1
 EVX SP
evstwhex 0 0 0 1 0 0
 rS
 rA
 rB
 0 1 1 0 0
 1
 1 0 0
 0
 0
 EVX SP
2
evstwhe 0 0 0 1 0 0
 rS
 rA
 UIMM 0 1 1 0 0
 1
 1 0 0
 0
 1
 EVX SP
evstwhox 0 0 0 1 0 0
 rS
 rA
 rB
 0 1 1 0 0
 1
 1 0 1
 0
 0
 EVX SP
2
evstwho 0 0 0 1 0 0
 rS
 rA
 UIMM
 0 1 1 0 0
 1
 1 0 1
 0
 1
 EVX SP
evstwwex 0 0 0 1 0 0
 rS
 rA
 rB
 0 1 1 0 0
 1
 1 1 0
 0
 0
 EVX SP
evstwwe 0 0 0 1 0 0
 rS
 rA
 UIMM 3
 0 1 1 0 0
 1
 1 1 0
 0
 1
 EVX SP
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-91
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
evstwwox 0 0 0 1 0 0
 rS
 rA
 rB
 0 1 1 0 0
 1
 1 1 1
 0
 0
 EVX SP
3
evstwwo 0 0 0 1 0 0
 rS
 rA
 UIMM 0 1 1 0 0
 1
 1 1 1
 0
 1
 EVX SP
vaddshs 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 0 1
 0
 0 0 0
 0
 0
 VX
 V
vminsh 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 0 1
 0
 0 0 0
 1
 0
 VX
 V
vsrah 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 0 1
 0
 0 0 1
 0
 0
 VX
 V
vcmpgtsh 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 0 1
 0
 0 0 1
 1
 0
 VC
 V
vmulesh 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 0 1
 0
 0 1 0
 0
 0
 VX
 V
vcfsx 0 0 0 1 0 0
 vD
 UIMM
 vB
 0 1 1 0 1
 0
 0 1 0
 1
 0
 VX
 V
vspltish 0 0 0 1 0 0
 vD
 SIMM
 ///
 0 1 1 0 1
 0
 0 1 1
 0
 0
 VX
 V
vupkhpx 0 0 0 1 0 0
 vD
 ///
 vB
 0 1 1 0 1
 0
 0 1 1
 1
 0
 VX
 V
vaddsws 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 1 0
 0
 0 0 0
 0
 0
 VX
 V
vminsw 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 1 0
 0
 0 0 0
 1
 0
 VX
 V
vsraw 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 1 0
 0
 0 0 1
 0
 0
 VX
 V
vcmpgtsw 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 1 0
 0
 0 0 1
 1
 0
 VC
 V
vctuxs 0 0 0 1 0 0
 vD
 UIMM
 vB
 0 1 1 1 0
 0
 0 1 0
 1
 0
 VX
 V
vspltisw 0 0 0 1 0 0
 vD
 SIMM
 ///
 0 1 1 1 0
 0
 0 1 1
 0
 0
 VX
 V
vcmpbfp 0 0 0 1 0 0
 vD
 vA
 vB
 0 1 1 1 1
 0
 0 0 1
 1
 0
 VC
 V
vctsxs 0 0 0 1 0 0
 vD
 UIMM
 vB
 0 1 1 1 1
 0
 0 1 0
 1
 0
 VX
 V
vupklpx 0 0 0 1 0 0
 vD
 ///
 vB
 0 1 1 1 1
 0
 0 1 1
 1
 0
 VX
 V
vsububm 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 0
 0
 0 0 0
 0
 0
 VX
 V
vavgub 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 0
 0
 0 0 0
 1
 0
 VX
 V
evmhessf 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 0
 0 0 0
 1
 1
 EVX SP
vabsdub 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 0
 0
 0 0 0
 1
 1
 VX
 V
vand 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 0
 0
 0 0 1
 0
 0
 VX
 V
vcmpequb. 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 0
 0
 0 0 1
 1
 0
 VC
 V
evmhossf 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 0
 0 0 1
 1
 1
 EVX SP
evmheumi 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 0
 0 1 0
 0
 0
 EVX SP
evmhesmi 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 0
 0 1 0
 0
 1
 EVX SP
vmaxfp 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 0
 0
 0 1 0
 1
 0
 VX
 V
evmhesmf 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 0
 0 1 0
 1
 1
 EVX SP
evmhoumi 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 0
 0 1 1
 0
 0
 EVX SP
vslo 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 0
 0
 0 1 1
 0
 0
 VX
 V
evmhosmi 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 0
 0 1 1
 0
 1
 EVX SP
evmhosmf 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 0
 0 1 1
 1
 1
 EVX SP
evmhessfa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 1
 0 0 0
 1
 1
 EVX SP
A-92
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
evmhossfa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 1
 0 0 1
 1
 1
 EVX SP
evmheumia 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 1
 0 1 0
 0
 0
 EVX SP
evmhesmia 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 1
 0 1 0
 0
 1
 EVX SP
evmhesmfa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 1
 0 1 0
 1
 1
 EVX SP
evmhoumia 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 1
 0 1 1
 0
 0
 EVX SP
evmhosmia 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 1
 0 1 1
 0
 1
 EVX SP
evmhosmfa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 0
 1
 0 1 1
 1
 1
 EVX SP
vsubuhm 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 1
 0
 0 0 0
 0
 0
 VX
 V
vavguh 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 1
 0
 0 0 0
 1
 0
 VX
 V
vabsduh 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 1
 0
 0 0 0
 1
 1
 VX
 V
vandc 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 1
 0
 0 0 1
 0
 0
 VX
 V
vcmpequh. 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 1
 0
 0 0 1
 1
 0
 VC
 V
evmwhssf 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 0
 0 0 1
 1
 1
 EVX SP
evmwlumi 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 0
 0 1 0
 0
 0
 EVX SP
vminfp 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 1
 0
 0 1 0
 1
 0
 VX
 V
evmwhumi 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 0
 0 1 1
 0
 0
 EVX SP
vsro 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 0 1
 0
 0 1 1
 0
 0
 VX
 V
evmwhsmi 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 0
 0 1 1
 0
 1
 EVX SP
evmwhsmf 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 0
 0 1 1
 1
 1
 EVX SP
evmwssf 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 0
 1 0 0
 1
 1
 EVX SP
evmwumi 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 0
 1 1 0
 0
 0
 EVX SP
evmwsmi 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 0
 1 1 0
 0
 1
 EVX SP
evmwsmf 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 0
 1 1 0
 1
 1
 EVX SP
evmwhssfa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 1
 0 0 1
 1
 1
 EVX SP
evmwlumia 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 1
 0 1 0
 0
 0
 EVX SP
evmwhumia 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 1
 0 1 1
 0
 0
 EVX SP
evmwhsmia 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 1
 0 1 1
 0
 1
 EVX SP
evmwhsmfa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 1
 0 1 1
 1
 1
 EVX SP
evmwssfa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 1
 1 0 0
 1
 1
 EVX SP
evmwumia 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 1
 1 1 0
 0
 0
 EVX SP
evmwsmia 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 1
 1 1 0
 0
 1
 EVX SP
evmwsmfa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 0 1
 1
 1 1 0
 1
 1
 EVX SP
vsubuwm 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 1 0
 0
 0 0 0
 0
 0
 VX
 V
vavguw 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 1 0
 0
 0 0 0
 1
 0
 VX
 V
vabsduw 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 1 0
 0
 0 0 0
 1
 1
 VX
 V
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-93
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
vor 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 1 0
 0
 0 0 1
 0
 0
 VX
 V
vcmpequw. 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 1 0
 0
 0 0 1
 1
 0
 VC
 V
evaddusiaaw 0 0 0 1 0 0
 rD
 rA
 ///
 1 0 0 1 1
 0
 0 0 0
 0
 0
 EVX SP
evaddssiaaw 0 0 0 1 0 0
 rD
 rA
 ///
 1 0 0 1 1
 0
 0 0 0
 0
 1
 EVX SP
evsubfusiaaw 0 0 0 1 0 0
 rD
 rA
 ///
 1 0 0 1 1
 0
 0 0 0
 1
 0
 EVX SP
evsubfssiaaw 0 0 0 1 0 0
 rD
 rA
 ///
 1 0 0 1 1
 0
 0 0 0
 1
 1
 EVX SP
evmra 0 0 0 1 0 0
 rD
 rA
 ///
 1 0 0 1 1
 0
 0 0 1
 0
 0
 EVX SP
vxor 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 1 1
 0
 0 0 1
 0
 0
 VX
 V
evdivws 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 1 1
 0
 0 0 1
 1
 0
 EVX SP
vcmpeqfp. 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 0 1 1
 0
 0 0 1
 1
 0
 VC
 V
evdivwu 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 0 1 1
 0
 0 0 1
 1
 1
 EVX SP
evaddumiaaw 0 0 0 1 0 0
 rD
 rA
 ///
 1 0 0 1 1
 0
 0 1 0
 0
 0
 EVX SP
evaddsmiaaw 0 0 0 1 0 0
 rD
 rA
 ///
 1 0 0 1 1
 0
 0 1 0
 0
 1
 EVX SP
evsubfumiaaw 0 0 0 1 0 0
 rD
 rA
 ///
 1 0 0 1 1
 0
 0 1 0
 1
 0
 EVX SP
evsubfsmiaaw 0 0 0 1 0 0
 rD
 rA
 ///
 1 0 0 1 1
 0
 0 1 0
 1
 1
 EVX SP
evmheusiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 0 0
 0
 0
 EVX SP
evmhessiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 0 0
 0
 1
 EVX SP
vavgsb 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 1 0 0
 0
 0 0 0
 1
 0
 VX
 V
evmhessfaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 0 0
 1
 1
 EVX SP
evmhousiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 0 1
 0
 0
 EVX SP
vnor 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 1 0 0
 0
 0 0 1
 0
 0
 VX
 V
evmhossiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 0 1
 0
 1
 EVX SP
evmhossfaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 0 1
 1
 1
 EVX SP
evmheumiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 1 0
 0
 0
 EVX SP
evmhesmiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 1 0
 0
 1
 EVX SP
evmhesmfaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 1 0
 1
 1
 EVX SP
evmhoumiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 1 1
 0
 0
 EVX SP
evmhosmiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 1 1
 0
 1
 EVX SP
evmhosmfaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 0
 0 1 1
 1
 1
 EVX SP
evmhegumiaa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 1
 0 1 0
 0
 0
 EVX SP
evmhegsmiaa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 1
 0 1 0
 0
 1
 EVX SP
evmhegsmfaa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 1
 0 1 0
 1
 1
 EVX SP
evmhogumiaa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 1
 0 1 1
 0
 0
 EVX SP
evmhogsmiaa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 1
 0 1 1
 0
 1
 EVX SP
evmhogsmfaa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 0
 1
 0 1 1
 1
 1
 EVX SP
A-94
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
evmwlusiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 1
 0
 0 0 0
 0
 0
 EVX SP
evmwlssiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 1
 0
 0 0 0
 0
 1
 EVX SP
vavgsh 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 1 0 1
 0
 0 0 0
 1
 0
 VX
 V
evmwhssmaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 1
 0
 0 0 1
 0
 1
 EVX SP
evmwlumiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 1
 0
 0 1 0
 0
 0
 EVX SP
evmwlsmiaaw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 1
 0
 0 1 0
 0
 1
 EVX SP
evmwssfaa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 1
 0
 1 0 0
 1
 1
 EVX SP
evmwumiaa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 1
 0
 1 1 0
 0
 0
 EVX SP
evmwsmiaa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 1
 0
 1 1 0
 0
 1
 EVX SP
evmwsmfaa 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 0 1
 0
 1 1 0
 1
 1
 EVX SP
evmheusianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 0 0
 0
 0
 EVX SP
vsubcuw 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 1 1 0
 0
 0 0 0
 0
 0
 VX
 V
evmhessianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 0 0
 0
 1
 EVX SP
vavgsw 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 1 1 0
 0
 0 0 0
 1
 0
 VX
 V
evmhessfanw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 0 0
 1
 1
 EVX SP
evmhousianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 0 1
 0
 0
 EVX SP
evmhossianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 0 1
 0
 1
 EVX SP
evmhossfanw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 0 1
 1
 1
 EVX SP
evmheumianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 1 0
 0
 0
 EVX SP
evmhesmianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 1 0
 0
 1
 EVX SP
evmhesmfanw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 1 0
 1
 1
 EVX SP
evmhoumianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 1 1
 0
 0
 EVX SP
evmhosmianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 1 1
 0
 1
 EVX SP
evmhosmfanw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 0
 0 1 1
 1
 1
 EVX SP
evmhegumian 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 1
 0 1 0
 0
 0
 EVX SP
evmhegsmian 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 1
 0 1 0
 0
 1
 EVX SP
evmhegsmfan 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 1
 0 1 0
 1
 1
 EVX SP
evmhogumian 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 1
 0 1 1
 0
 0
 EVX SP
evmhogsmian 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 1
 0 1 1
 0
 1
 EVX SP
evmhogsmfan 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 0
 1
 0 1 1
 1
 1
 EVX SP
evmwlusianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 1
 0
 0 0 0
 0
 0
 EVX SP
evmwlssianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 1
 0
 0 0 0
 0
 1
 EVX SP
vcmpgefp. 0 0 0 1 0 0
 vD
 vA
 vB
 1 0 1 1 1
 0
 0 0 1
 1
 0
 VC
 V
evmwlumianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 1
 0
 0 1 0
 0
 0
 EVX SP
evmwlsmianw 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 1
 0
 0 1 0
 0
 1
 EVX SP
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-95
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
evmwssfan 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 1
 0
 1 0 0
 1
 1
 EVX SP
evmwumian 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 1
 0
 1 1 0
 0
 0
 EVX SP
evmwsmian 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 1
 0
 1 1 0
 0
 1
 EVX SP
evmwsmfan 0 0 0 1 0 0
 rD
 rA
 rB
 1 0 1 1 1
 0
 1 1 0
 1
 1
 EVX SP
vsububs 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 0 0 0
 0
 0 0 0
 0
 0
 VX
 V
mfvscr 0 0 0 1 0 0
 vD
 ///
 ///
 1 1 0 0 0
 0
 0 0 1
 0
 0
 VX
 V
vcmpgtub. 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 0 0 0
 0
 0 0 1
 1
 0
 VC
 V
vsum4ubs 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 0 0 0
 0
 0 1 0
 0
 0
 VX
 V
vsubuhs 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 0 0 1
 0
 0 0 0
 0
 0
 VX
 V
mtvscr 0 0 0 1 0 0
 ///
 ///
 vB
 1 1 0 0 1
 0
 0 0 1
 0
 0
 VX
 V
vcmpgtuh. 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 0 0 1
 0
 0 0 1
 1
 0
 VC
 V
vsum4shs 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 0 0 1
 0
 0 1 0
 0
 0
 VX
 V
vsubuws 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 0 1 0
 0
 0 0 0
 0
 0
 VX
 V
vcmpgtuw. 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 0 1 0
 0
 0 0 1
 1
 0
 VC
 V
vsum2sws 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 0 1 0
 0
 0 1 0
 0
 0
 VX
 V
vcmpgtfp. 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 0 1 1
 0
 0 0 1
 1
 0
 VC
 V
vsubsbs 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 1 0 0
 0
 0 0 0
 0
 0
 VX
 V
vcmpgtsb. 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 1 0 0
 0
 0 0 1
 1
 0
 VC
 V
vsum4sbs 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 1 0 0
 0
 0 1 0
 0
 0
 VX
 V
vsubshs 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 1 0 1
 0
 0 0 0
 0
 0
 VX
 V
vcmpgtsh. 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 1 0 1
 0
 0 0 1
 1
 0
 VC
 V
vsubsws 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 1 1 0
 0
 0 0 0
 0
 0
 VX
 V
vcmpgtsw. 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 1 1 0
 0
 0 0 1
 1
 0
 VC
 V
vsumsws 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 1 1 0
 0
 0 1 0
 0
 0
 VX
 V
vcmpbfp. 0 0 0 1 0 0
 vD
 vA
 vB
 1 1 1 1 1
 0
 0 0 1
 1
 0
 VC
 V
mulli 0 0 0 1 1 1
 rD
 rA
 SIMM
 D
subfic 0 0 1 0 0 0
 rD
 rA
 SIMM
 D
cmpli 0 0 1 0 1 0
 crD
 /
 L
 rA
 UIMM
 D
cmpi 0 0 1 0 1 1
 crD
 /
 L
 rA
 SIMM
 D
addic 0 0 1 1 0 0
 rD
 rA
 SIMM
 D
addic. 0 0 1 1 0 1
 rD
 rA
 SIMM
 D
addi 0 0 1 1 1 0
 rD
 rA
 SIMM
 D
addis 0 0 1 1 1 1
 rD
 rA
 SIMM
 D
bc 0 1 0 0 0 0
 BO
 BI
 BD
 0
 0
 B
bcl 0 1 0 0 0 0
 BO
 BI
 BD
 0
 1
 B
A-96
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
bca 0 1 0 0 0 0
 BO
 BI
 BD
 1
 0
 B
bcla 0 1 0 0 0 0
 BO
 BI
 BD
 1
 1
 B
sc 0 1 0 0 0 1
 ///
 LEV
 ///
 1
 /
 SC
b 0 1 0 0 1 0
 LI
 0
 0
 I
bl 0 1 0 0 1 0
 LI
 0
 1
 I
ba 0 1 0 0 1 0
 LI
 1
 0
 I
bla 0 1 0 0 1 0
 LI
 1
 1
 I
mcrf 0 1 0 0 1 1
 crD
 //
 crfS
 ///
 0 0 0 0 0
 0
 0 0 0
 0
 /
 XL
bclr 0 1 0 0 1 1
 BO
 BI
 ///
 BH
 0 0 0 0 0
 1
 0 0 0
 0
 0
 XL
bclrl 0 1 0 0 1 1
 BO
 BI
 ///
 BH
 0 0 0 0 0
 1
 0 0 0
 0
 1
 XL
crnor 0 1 0 0 1 1
 crbD
 crbA
 crbB
 0 0 0 0 1
 0
 0 0 0
 1
 /
 XL
rfmci 0 1 0 0 1 1
 ///
 0 0 0 0 1
 0
 0 1 1
 0
 /
 XL
 Embedded
rfdi 0 1 0 0 1 1
 ///
 0 0 0 0 1
 0
 0 1 1
 1
 /
 X
 E.ED
rfi 0 1 0 0 1 1
 ///
 0 0 0 0 1
 1
 0 0 1
 0
 /
 XL
 Embedded
rfci 0 1 0 0 1 1
 ///
 0 0 0 0 1
 1
 0 0 1
 1
 /
 XL
 Embedded
rfgi 0 1 0 0 1 1
 ///
 0 0 0 1 1
 0
 0 1 1
 0
 /
 X
 E.HV
crandc 0 1 0 0 1 1
 crbD
 crbA
 crbB
 0 0 1 0 0
 0
 0 0 0
 1
 /
 XL
isync 0 1 0 0 1 1
 ///
 0 0 1 0 0
 1
 0 1 1
 0
 /
 XL
crxor 0 1 0 0 1 1
 crbD
 crbA
 crbB
 0 0 1 1 0
 0
 0 0 0
 1
 /
 XL
dnh 0 1 0 0 1 1
 DUI
 DCTL
 0 0 0 0 0 0 0 1 1 0
 0
 0 1 1
 0
 /
 X
 E.ED
crnand 0 1 0 0 1 1
 crbD
 crbA
 crbB
 0 0 1 1 1
 0
 0 0 0
 1
 /
 XL
crand 0 1 0 0 1 1
 crbD
 crbA
 crbB
 0 1 0 0 0
 0
 0 0 0
 1
 /
 XL
creqv 0 1 0 0 1 1
 crbD
 crbA
 crbB
 0 1 0 0 1
 0
 0 0 0
 1
 /
 XL
crorc 0 1 0 0 1 1
 crbD
 crbA
 crbB
 0 1 1 0 1
 0
 0 0 0
 1
 /
 XL
cror 0 1 0 0 1 1
 crbD
 crbA
 crbB
 0 1 1 1 0
 0
 0 0 0
 1
 /
 XL
bcctr 0 1 0 0 1 1
 BO
 BI
 ///
 BH
 1 0 0 0 0
 1
 0 0 0
 0
 0
 XL
bcctrl 0 1 0 0 1 1
 BO
 BI
 ///
 BH
 1 0 0 0 0
 1
 0 0 0
 0
 1
 XL
rlwimi 0 1 0 1 0 0
 rS
 rA
 SH
 MB
 ME
 0
 M
rlwimi. 0 1 0 1 0 0
 rS
 rA
 SH
 MB
 ME
 1
 M
rlwinm 0 1 0 1 0 1
 rS
 rA
 SH
 MB
 ME
 0
 M
rlwinm. 0 1 0 1 0 1
 rS
 rA
 SH
 MB
 ME
 1
 M
rlwnm 0 1 0 1 1 1
 rS
 rA
 rB
 MB
 ME
 0
 M
rlwnm. 0 1 0 1 1 1
 rS
 rA
 rB
 MB
 ME
 1
 M
ori 0 1 1 0 0 0
 rS
 rA
 UIMM
 D
oris 0 1 1 0 0 1
 rS
 rA
 UIMM
 D
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-97
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
xori 0 1 1 0 1 0
 rS
 rA
 UIMM
 D
xoris 0 1 1 0 1 1
 rS
 rA
 UIMM
 D
andi. 0 1 1 1 0 0
 rS
 rA
 UIMM
 D
andis. 0 1 1 1 0 1
 rS
 rA
 UIMM
 D
rldicl 0 1 1 1 1 0
 rS
 rA
 sh1–5
 mb1–5
 mb0 0
 0 0 sh0 0
 MD
 64
rldicl. 0 1 1 1 1 0
 rS
 rA
 sh1–5
 mb1–5
 mb0 0
 0 0 sh0 1
 MD
 64
rldicr 0 1 1 1 1 0
 rS
 rA
 sh1–5
 me1–5
 me0 0
 0 1 sh0 0
 MD
 64
rldicr. 0 1 1 1 1 0
 rS
 rA
 sh1–5
 me1–5
 me0 0
 0 1 sh0 1
 MD
 64
rldic 0 1 1 1 1 0
 rS
 rA
 sh1–5
 mb1–5
 mb0 0
 1 0 sh0 0
 MD
 64
rldic. 0 1 1 1 1 0
 rS
 rA
 sh1–5
 mb1–5
 mb0 0
 1 0 sh0 1
 MD
 64
rldimi 0 1 1 1 1 0
 rS
 rA
 sh1–5
 mb1–5
 mb0 0
 1 1 sh0 0
 MD
 64
rldimi. 0 1 1 1 1 0
 rS
 rA
 sh1–5
 mb1–5
 mb0 0
 1 1 sh0 1
 MD
 64
rldcl 0 1 1 1 1 0
 rS
 rA
 rB
 mb1–5
 mb0 1
 0 0
 0
 0
 MDS 64
rldcl. 0 1 1 1 1 0
 rS
 rA
 rB
 mb1–5
 mb0 1
 0 0
 0
 1
 MDS 64
rldcr 0 1 1 1 1 0
 rS
 rA
 rB
 me1–5
 me0 1
 0 0
 1
 0
 MDS 64
rldcr. 0 1 1 1 1 0
 rS
 rA
 rB
 me1–5
 me0 1
 0 0
 1
 1
 MDS 64
cmp 0 1 1 1 1 1
 crD
 /
 L
 rA
 rB
 0 0 0 0 0
 0
 0 0 0
 0
 /
 X
tw 0 1 1 1 1 1
 TO
 rA
 rB
 0 0 0 0 0
 0
 0 1 0
 0
 /
 X
lvsl 0 1 1 1 1 1
 vD
 rA
 rB
 0 0 0 0 0
 0
 0 1 1
 0
 /
 X
 V
lvebx 0 1 1 1 1 1
 vD
 rA
 rB
 0 0 0 0 0
 0
 0 1 1
 1
 /
 X
 V
subfc 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 0
 0
 1 0 0
 0
 0
 X
subfc. 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 0
 0
 1 0 0
 0
 1
 X
mulhdu 0 1 1 1 1 1
 rD
 rA
 rB
 /
 0 0 0 0
 0
 1 0 0
 1
 0
 X
 64
mulhdu. 0 1 1 1 1 1
 rD
 rA
 rB
 /
 0 0 0 0
 0
 1 0 0
 1
 1
 X
 64
addc 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 0
 0
 1 0 1
 0
 0
 X
addc. 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 0
 0
 1 0 1
 0
 1
 X
mulhwu 0 1 1 1 1 1
 rD
 rA
 rB
 /
 0 0 0 0
 0
 1 0 1
 1
 0
 X
mulhwu. 0 1 1 1 1 1
 rD
 rA
 rB
 /
 0 0 0 0
 0
 1 0 1
 1
 1
 X
isel 0 1 1 1 1 1
 rD
 rA
 rB
 crb
 0
 1 1 1
 1
 0
 A
tlbilx 0 1 1 1 1 1
 0
 ///
 T
 rA
 rB
 0 0 0 0 0
 1
 0 0 1
 0
 /
 X
 Embedded
mfcr 0 1 1 1 1 1
 rD
 0
 ///
 0 0 0 0 0
 1
 0 0 1
 1
 /
 X
mfocrf 0 1 1 1 1 1
 rD
 1
 CRM
 /
 0 0 0 0 0
 1
 0 0 1
 1
 /
 X
lwarx 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 0
 1
 0 1 0
 0
 /
 X
ldx 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 0
 1
 0 1 0
 1
 /
 X
 64
icbt 0 1 1 1 1 1
 CT
 rA
 rB
 0 0 0 0 0
 1
 0 1 1
 0
 /
 X
 Embedded
A-98
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
lwzx 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 0
 1
 0 1 1
 1
 /
 X
slw 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 0 0 0
 1
 1 0 0
 0
 0
 X
slw. 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 0 0 0
 1
 1 0 0
 0
 1
 X
cntlzw 0 1 1 1 1 1
 rS
 rA
 ///
 0 0 0 0 0
 1
 1 0 1
 0
 0
 X
cntlzw. 0 1 1 1 1 1
 rS
 rA
 ///
 0 0 0 0 0
 1
 1 0 1
 0
 1
 X
sld 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 0 0 0
 1
 1 0 1
 1
 0
 X
 64
sld. 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 0 0 0
 1
 1 0 1
 1
 1
 X
 64
and 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 0 0 0
 1
 1 1 0
 0
 0
 X
and. 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 0 0 0
 1
 1 1 0
 0
 1
 X
ldepx 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 0
 1
 1 1 0
 1
 /
 X
 E.PD, 64
lwepx 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 0
 1
 1 1 1
 1
 /
 X
 E.PD
cmpl 0 1 1 1 1 1
 /
 L
 rA
 rB
 ///
 0 0 0 0 1
 0
 0 0 0
 0
 /
 X
lvsr 0 1 1 1 1 1
 vD
 rA
 rB
 0 0 0 0 1
 0
 0 1 1
 0
 /
 X
 V
lvehx 0 1 1 1 1 1
 vD
 rA
 rB
 0 0 0 0 1
 0
 0 1 1
 1
 /
 X
 V
subf 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 1
 0
 1 0 0
 0
 0
 X
subf. 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 1
 0
 1 0 0
 0
 1
 X
mviwsplt 0 1 1 1 1 1
 vD
 rA
 rB
 0 0 0 0 1
 0
 1 1 1
 0
 /
 X
 V
lbarx 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 1
 1
 0 1 0
 0
 /
 X
 ER
ldux 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 1
 1
 0 1 0
 1
 /
 X
 64
dcbst 0 1 1 1 1 1
 ///
 rA
 rB
 0 0 0 0 1
 1
 0 1 1
 0
 /
 X
lwzux 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 0 1
 1
 0 1 1
 1
 /
 X
cntlzd 0 1 1 1 1 1
 rS
 rA
 ///
 0 0 0 0 1
 1
 1 0 1
 0
 0
 X
 64
cntlzd. 0 1 1 1 1 1
 rS
 rA
 ///
 0 0 0 0 1
 1
 1 0 1
 0
 1
 X
 64
andc 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 0 0 1
 1
 1 1 0
 0
 0
 X
andc. 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 0 0 1
 1
 1 1 0
 0
 1
 X
wait 0 1 1 1 1 1
 ///
 WC WH
 ///
 0 0 0 0 1
 1
 1 1 1
 0
 /
 X
 WT
dcbstep 0 1 1 1 1 1
 ///
 rA
 rB
 0 0 0 0 1
 1
 1 1 1
 1
 /
 X
 E.PD
td 0 1 1 1 1 1
 TO
 rA
 rB
 0 0 0 1 0
 0
 0 1 0
 0
 /
 X
 64
lvewx 0 1 1 1 1 1
 vD
 rA
 rB
 0 0 0 1 0
 0
 0 1 1
 1
 /
 X
 V
mulhd 0 1 1 1 1 1
 rD
 rA
 rB
 /
 0 0 1 0
 0
 1 0 0
 1
 0
 X
 64
mulhd. 0 1 1 1 1 1
 rD
 rA
 rB
 /
 0 0 1 0
 0
 1 0 0
 1
 1
 X
 64
mulhw 0 1 1 1 1 1
 rD
 rA
 rB
 /
 0 0 1 0
 0
 1 0 1
 1
 0
 X
mulhw. 0 1 1 1 1 1
 rD
 rA
 rB
 /
 0 0 1 0
 0
 1 0 1
 1
 1
 X
mfmsr 0 1 1 1 1 1
 rD
 ///
 0 0 0 1 0
 1
 0 0 1
 1
 /
 X
ldarx 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 1 0
 1
 0 1 0
 0
 /
 X
 64
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-99
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
dcbf 0 1 1 1 1 1
 ///
 rA
 rB
 0 0 0 1 0
 1
 0 1 1
 0
 /
 X
lbzx 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 1 0
 1
 0 1 1
 1
 /
 X
lbepx 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 1 0
 1
 1 1 1
 1
 /
 X
 E.PD
dni 0 1 1 1 1 1
 DUI
 DCTL
 0 0 0 0 0 0 0 0 1 1
 0
 0 0 0
 1
 1
 X
 E.ED
lvx 0 1 1 1 1 1
 vD
 rA
 rB
 0 0 0 1 1
 0
 0 1 1
 1
 /
 X
 V
neg 0 1 1 1 1 1
 rD
 rA
 ///
 0 0 0 1 1
 0
 1 0 0
 0
 0
 X
neg. 0 1 1 1 1 1
 rD
 rA
 ///
 0 0 0 1 1
 0
 1 0 0
 0
 1
 X
mvidsplt 0 1 1 1 1 1
 vD
 rA
 rB
 0 0 0 1 1
 0
 1 1 1
 0
 /
 X
 V, 64
lharx 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 1 1
 1
 0 1 0
 0
 /
 X
 ER
lbzux 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 0 1 1
 1
 0 1 1
 1
 /
 X
popcntb 0 1 1 1 1 1
 rS
 rA
 ///
 0 0 0 1 1
 1
 1 0 1
 0
 /
 X
nor 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 0 1 1
 1
 1 1 0
 0
 0
 X
nor. 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 0 1 1
 1
 1 1 0
 0
 1
 X
dcbfep 0 1 1 1 1 1
 ///
 rA
 rB
 0 0 0 1 1
 1
 1 1 1
 1
 /
 X
 E.PD
wrtee 0 1 1 1 1 1
 rS
 ///
 0 0 1 0 0
 0
 0 0 1
 1
 /
 X
 Embedded
dcbtstls 0 1 1 1 1 1
 CT
 rA
 rB
 0 0 1 0 0
 0
 0 1 1
 0
 /
 X
 E.CL
stvebx 0 1 1 1 1 1
 vS
 rA
 rB
 0 0 1 0 0
 0
 0 1 1
 1
 /
 X
 V
subfe 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 1 0 0
 0
 1 0 0
 0
 0
 X
subfe. 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 1 0 0
 0
 1 0 0
 0
 1
 X
adde 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 1 0 0
 0
 1 0 1
 0
 0
 X
adde. 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 1 0 0
 0
 1 0 1
 0
 1
 X
mtcrf 0 1 1 1 1 1
 rS
 0
 CRM
 /
 0 0 1 0 0
 1
 0 0 0
 0
 /
 XFX
mtocrf 0 1 1 1 1 1
 rS
 1
 CRM
 /
 0 0 1 0 0
 1
 0 0 0
 0
 /
 XFX
mtmsr 0 1 1 1 1 1
 rS
 ///
 0 0 1 0 0
 1
 0 0 1
 0
 /
 X
stdx 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 0 0
 1
 0 1 0
 1
 /
 X
 64
stwcx. 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 0 0
 1
 0 1 1
 0
 1
 X
stwx 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 0 0
 1
 0 1 1
 1
 /
 D
prtyw 0 1 1 1 1 1
 rS
 rA
 ///
 0 0 1 0 0
 1
 1 0 1
 0
 /
 X
stdepx 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 0 0
 1
 1 1 0
 1
 /
 X
 E.PD, 64
stwepx 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 0 0
 1
 1 1 1
 1
 /
 X
 E.PD
wrteei 0 1 1 1 1 1
 ///
 E
 ///
 0 0 1 0 1
 0
 0 0 1
 1
 /
 X
 Embedded
dcbtls 0 1 1 1 1 1
 CT
 rA
 rB
 0 0 1 0 1
 0
 0 1 1
 0
 /
 X
 E.CL
stvehx 0 1 1 1 1 1
 vS
 rA
 rB
 0 0 1 0 1
 0
 0 1 1
 1
 /
 X
 V
stdux 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 0 1
 1
 0 1 0
 1
 /
 X
 64
stwux 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 0 1
 1
 0 1 1
 1
 /
 D
A-100
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
prtyd 0 1 1 1 1 1
 rS
 rA
 ///
 0 0 1 0 1
 1
 1 0 1
 0
 /
 X
 64
icblq. 0 1 1 1 1 1
 CT
 rA
 rB
 0 0 1 1 0
 0
 0 1 1
 0
 /
 X
 E.CL
stvewx 0 1 1 1 1 1
 vS
 rA
 rB
 0 0 1 1 0
 0
 0 1 1
 1
 /
 X
 V
subfze 0 1 1 1 1 1
 rD
 rA
 ///
 0 0 1 1 0
 0
 1 0 0
 0
 0
 X
subfze. 0 1 1 1 1 1
 rD
 rA
 ///
 0 0 1 1 0
 0
 1 0 0
 0
 1
 X
addze 0 1 1 1 1 1
 rD
 rA
 ///
 0 0 1 1 0
 0
 1 0 1
 0
 0
 X
addze. 0 1 1 1 1 1
 rD
 rA
 ///
 0 0 1 1 0
 0
 1 0 1
 0
 1
 X
msgsnd 0 1 1 1 1 1
 ///
 ///
 rB
 0 0 1 1 0
 0
 1 1 1
 0
 /
 X
 E.PC
stdcx. 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 1 0
 1
 0 1 1
 0
 1
 X
 64
stbx 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 1 0
 1
 0 1 1
 1
 /
 X
stbepx 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 1 0
 1
 1 1 1
 1
 /
 X
 E.PD
icblc 0 1 1 1 1 1
 CT
 rA
 rB
 0 0 1 1 1
 0
 0 1 1
 0
 /
 X
 E.CL
stvx 0 1 1 1 1 1
 vS
 rA
 rB
 0 0 1 1 1
 0
 0 1 1
 1
 /
 X
 V
subfme 0 1 1 1 1 1
 rD
 rA
 ///
 0 0 1 1 1
 0
 1 0 0
 0
 0
 X
subfme. 0 1 1 1 1 1
 rD
 rA
 ///
 0 0 1 1 1
 0
 1 0 0
 0
 1
 X
mulld 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 1 1 1
 0
 1 0 0
 1
 0
 X
 64
mulld. 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 1 1 1
 0
 1 0 0
 1
 1
 X
 64
addme 0 1 1 1 1 1
 rD
 rA
 ///
 0 0 1 1 1
 0
 1 0 1
 0
 0
 X
addme. 0 1 1 1 1 1
 rD
 rA
 ///
 0 0 1 1 1
 0
 1 0 1
 0
 1
 X
mullw 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 1 1 1
 0
 1 0 1
 1
 0
 X
mullw. 0 1 1 1 1 1
 rD
 rA
 rB
 0 0 1 1 1
 0
 1 0 1
 1
 1
 X
msgclr 0 1 1 1 1 1
 ///
 ///
 rB
 0 0 1 1 1
 0
 1 1 1
 0
 /
 X
 E.PC
dcbtst 0 1 1 1 1 1
 TH
 rA
 rB
 0 0 1 1 1
 1
 0 1 1
 0
 /
 X
stbux 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 1 1
 1
 0 1 1
 1
 /
 X
bpermd 0 1 1 1 1 1
 rS
 rA
 rB
 0 0 1 1 1
 1
 1 1 0
 0
 /
 X
 64
dcbtstep 0 1 1 1 1 1
 TH
 rA
 rB
 0 0 1 1 1
 1
 1 1 1
 1
 /
 X
 E.PD
lvexbx 0 1 1 1 1 1
 vD
 rA
 rB
 0 1 0 0 0
 0
 0 1 0
 1
 /
 X
 V
lvepxl 0 1 1 1 1 1
 vD
 rA
 rB
 0 1 0 0 0
 0
 0 1 1
 1
 /
 X
 E.PD, V
sat 0 1 1 1 1 1
 rD
 rA
 A S I U O U S S
 0 1 0 0 0
 0
 1 0 0
 0
 0
 X
 ISAT
sat. 0 1 1 1 1 1
 rD
 rA
 A
 S I U
 U
 O S S
 0 1 0 0 0
 0
 1 0 0
 0
 1
 X
 ISAT
add 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 0 0
 0
 1 0 1
 0
 0
 X
add. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 0 0
 0
 1 0 1
 0
 1
 X
ehpriv 0 1 1 1 1 1
 OC
 0 1 0 0 0
 0
 1 1 1
 0
 /
 XL
 E.HV
dcbt 0 1 1 1 1 1
 TH
 rA
 rB
 0 1 0 0 0
 1
 0 1 1
 0
 /
 X
lhzx 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 0 0
 1
 0 1 1
 1
 /
 X
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-101
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
eqv 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 0 0
 1
 1 1 0
 0
 0
 X
eqv. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 0 0
 1
 1 1 0
 0
 1
 X
lhepx 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 0 0
 1
 1 1 1
 1
 /
 X
 E.PD
lvexhx 0 1 1 1 1 1
 vD
 rA
 rB
 0 1 0 0 1
 0
 0 1 0
 1
 /
 X
 V
lvepx 0 1 1 1 1 1
 vD
 rA
 rB
 0 1 0 0 1
 0
 0 1 1
 1
 /
 X
 E.PD, V
mulhss 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 0 1
 0
 1 0 1
 1
 0
 X
 ISAT
mulhss. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 0 1
 0
 1 0 1
 1
 1
 X
 ISAT
lhzux 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 0 1
 1
 0 1 1
 1
 /
 X
xor 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 0 0 1
 1
 1 1 0
 0
 0
 X
xor. 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 0 0 1
 1
 1 1 0
 0
 1
 X
dcbtep 0 1 1 1 1 1
 TH
 rA
 rB
 0 1 0 0 1
 1
 1 1 1
 1
 /
 X
 E.PD
mfdcr 0 1 1 1 1 1
 rD
 DCRN5–9
 DCRN0–4
 0 1 0 1 0
 0
 0 0 1
 1
 /
 XFX E.DC
lvexwx 0 1 1 1 1 1
 vD
 rA
 rB
 0 1 0 1 0
 0
 0 1 0
 1
 /
 X
 V
subfw 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 0
 0
 1 0 0
 0
 0
 X
 64
subfw. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 0
 0
 1 0 0
 0
 1
 X
 64
addw 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 0
 0
 1 0 1
 0
 0
 X
 64
addw. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 0
 0
 1 0 1
 0
 1
 X
 64
mfpmr 0 1 1 1 1 1
 rD
 PMRN5–9
 PMRN0–4
 0 1 0 1 0
 0
 1 1 1
 0
 /
 XFX E.PM
mfspr 0 1 1 1 1 1
 rD
 SPRN[5–9]
 SPRN[0–4]
 0 1 0 1 0
 1
 0 0 1
 1
 /
 XFX
lwax 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 0
 1
 0 1 0
 1
 /
 X
 64
dst 0 1 1 1 1 1
 0
 //
 STRM
 rA
 rB
 0 1 0 1 0
 1
 0 1 1
 0
 /
 X
 V
dstt 0 1 1 1 1 1
 1
 //
 STRM
 rA
 rB
 0 1 0 1 0
 1
 0 1 1
 0
 /
 X
 V
lhax 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 0
 1
 0 1 1
 1
 /
 X
lvxl 0 1 1 1 1 1
 vD
 rA
 rB
 0 1 0 1 1
 0
 0 1 1
 1
 /
 X
 V
subfwss 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 1
 0
 1 0 0
 0
 0
 X
 ISAT
subfwss. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 1
 0
 1 0 0
 0
 1
 X
 ISAT
addwss 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 1
 0
 1 0 1
 0
 0
 X
 ISAT
addwss. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 1
 0
 1 0 1
 0
 1
 X
 ISAT
mulwss 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 1
 0
 1 0 1
 1
 0
 X
 ISAT
mulwss. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 1
 0
 1 0 1
 1
 1
 X
 ISAT
mftmr 0 1 1 1 1 1
 rD
 TMRN[5–9]
 TMRN[0–4]
 0 1 0 1 1
 0
 1 1 1
 0
 /
 XFX EM.TM
mftb 0 1 1 1 1 1
 rD
 TBRN[5–9]
 TBRN[0–4]
 0 1 0 1 1
 1
 0 0 1
 1
 0
 XFX
lwaux 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 1
 1
 0 1 0
 1
 /
 X
 64
dstst 0 1 1 1 1 1
 0
 //
 STRM
 rA
 rB
 0 1 0 1 1
 1
 0 1 1
 0
 /
 X
 V
dststt 0 1 1 1 1 1
 1
 //
 STRM
 rA
 rB
 0 1 0 1 1
 1
 0 1 1
 0
 /
 X
 V
A-102
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
lhaux 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 0 1 1
 1
 0 1 1
 1
 /
 X
popcntw 0 1 1 1 1 1
 rS
 rA
 ///
 0 1 0 1 1
 1
 1 0 1
 0
 /
 X
stvexbx 0 1 1 1 1 1
 vS
 rA
 rB
 0 1 1 0 0
 0
 0 1 0
 1
 /
 X
 V
dcblc 0 1 1 1 1 1
 CT
 rA
 rB
 0 1 1 0 0
 0
 0 1 1
 0
 /
 X
 E.CL
subfh 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 0
 0
 1 0 0
 0
 0
 X
subfh. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 0
 0
 1 0 0
 0
 1
 X
addh 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 0
 0
 1 0 1
 0
 0
 X
addh. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 0
 0
 1 0 1
 0
 1
 X
divweu 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 0
 0
 1 0 1
 1
 0
 XO
divweu. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 0
 0
 1 0 1
 1
 1
 XO
sthx 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 1 0 0
 1
 0 1 1
 1
 /
 X
orc 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 1 0 0
 1
 1 1 0
 0
 0
 X
orc. 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 1 0 0
 1
 1 1 0
 0
 1
 X
sthepx 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 1 0 0
 1
 1 1 1
 1
 /
 X
 E.PD
stvexhx 0 1 1 1 1 1
 vS
 rA
 rB
 0 1 1 0 1
 0
 0 1 0
 1
 /
 X
 V
dcblq. 0 1 1 1 1 1
 CT
 rA
 rB
 0 1 1 0 1
 0
 0 1 1
 0
 1
 X
 E.CL
subfhss 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 1
 0
 1 0 0
 0
 0
 X
 ISAT
subfhss. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 1
 0
 1 0 0
 0
 1
 X
 ISAT
addhss 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 1
 0
 1 0 1
 0
 0
 X
 ISAT
addhss. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 1
 0
 1 0 1
 0
 1
 X
 ISAT
divwe 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 1
 0
 1 0 1
 1
 0
 XO
divwe. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 0 1
 0
 1 0 1
 1
 1
 XO
sthux 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 1 0 1
 1
 0 1 1
 1
 /
 X
miso 0 1 1 1 1 1
 1 1 0 1 0
 1
 1 0 1 0 1 1 0 1 0 0 1 1 0 1
 1
 1 1 0
 0
 0
 X
or 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 1 0 1
 1
 1 1 0
 0
 0
 X
or. 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 1 0 1
 1
 1 1 0
 0
 1
 X
mtdcr 0 1 1 1 1 1
 rS
 DCRN5–9
 DCRN0–4
 0 1 1 1 0
 0
 0 0 1
 1
 /
 XFX E.DC
stvexwx 0 1 1 1 1 1
 vS
 rA
 rB
 0 1 1 1 0
 0
 0 1 0
 1
 /
 X
 V
subfb 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 0
 0
 1 0 0
 0
 0
 X
subfb. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 0
 0
 1 0 0
 0
 1
 X
divdu 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 0
 0
 1 0 0
 1
 0
 X
 64
divdu. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 0
 0
 1 0 0
 1
 1
 X
 64
addb 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 0
 0
 1 0 1
 0
 0
 X
addb. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 0
 0
 1 0 1
 0
 1
 X
divwu 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 0
 0
 1 0 1
 1
 0
 X
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-103
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
divwu. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 0
 0
 1 0 1
 1
 1
 X
mtpmr 0 1 1 1 1 1
 rS
 PMRN5–9
 PMRN0–4
 0 1 1 1 0
 0
 1 1 1
 0
 /
 XFX E.PM
mtspr 0 1 1 1 1 1
 rS
 SPRN[5–9]
 SPRN[0–4]
 0 1 1 1 0
 1
 0 0 1
 1
 /
 XFX
dcbi 0 1 1 1 1 1
 ///
 rA
 rB
 0 1 1 1 0
 1
 0 1 1
 0
 /
 X
 Embedded
nand 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 1 1 0
 1
 1 1 0
 0
 0
 X
nand. 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 1 1 0
 1
 1 1 0
 0
 1
 X
dsn 0 1 1 1 1 1
 ///
 rA
 rB
 0 1 1 1 1
 0
 0 0 1
 1
 /
 X
 DS
icbtls 0 1 1 1 1 1
 CT
 rA
 rB
 0 1 1 1 1
 0
 0 1 1
 0
 /
 X
 E.CL
stvxl 0 1 1 1 1 1
 vS
 rA
 rB
 0 1 1 1 1
 0
 0 1 1
 1
 /
 X
 V
subfbss 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 1
 0
 1 0 0
 0
 0
 X
 ISAT
subfbss. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 1
 0
 1 0 0
 0
 1
 X
 ISAT
divd 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 1
 0
 1 0 0
 1
 0
 X
 64
divd. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 1
 0
 1 0 0
 1
 1
 X
 64
addbss 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 1
 0
 1 0 1
 0
 0
 X
 ISAT
addbss. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 1
 0
 1 0 1
 0
 1
 X
 ISAT
divw 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 1
 0
 1 0 1
 1
 0
 X
divw. 0 1 1 1 1 1
 rD
 rA
 rB
 0 1 1 1 1
 0
 1 0 1
 1
 1
 X
mttmr 0 1 1 1 1 1
 rS
 TMRN[5–9]
 TMRN[0–4]
 0 1 1 1 1
 0
 1 1 1
 0
 /
 XFX EM.TM
popcntd 0 1 1 1 1 1
 rS
 rA
 ///
 0 1 1 1 1
 1
 1 0 1
 0
 /
 X
 64
cmpb 0 1 1 1 1 1
 rS
 rA
 rB
 0 1 1 1 1
 1
 1 1 0
 0
 /
 X
mcrxr 0 1 1 1 1 1
 crD
 ///
 1 0 0 0 0
 0
 0 0 0
 0
 /
 X
lbdx 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 0 0
 0
 0 0 1
 1
 /
 X
 DS
subfco 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 0 0
 0
 1 0 0
 0
 0
 X
subfco. 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 0 0
 0
 1 0 0
 0
 1
 X
addco 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 0 0
 0
 1 0 1
 0
 0
 X
addco. 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 0 0
 0
 1 0 1
 0
 1
 X
ldbrx 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 0 0
 1
 0 1 0
 0
 /
 X
 64
lwbrx 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 0 0
 1
 0 1 1
 0
 /
 X
lfsx 0 1 1 1 1 1
 frD
 rA
 rB
 1 0 0 0 0
 1
 0 1 1
 1
 /
 X
srw 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 0 0 0
 1
 1 0 0
 0
 0
 X
srw. 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 0 0 0
 1
 1 0 0
 0
 1
 X
srd 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 0 0 0
 1
 1 0 1
 1
 0
 X
 64
srd. 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 0 0 0
 1
 1 0 1
 1
 1
 X
 64
lhdx 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 0 1
 0
 0 0 1
 0
 /
 X
 DS
lvtrx 0 1 1 1 1 1
 vD
 rA
 rB
 1 0 0 0 1
 0
 0 1 0
 1
 /
 X
 V
A-104
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
subfo 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 0 1
 0
 1 0 0
 0
 0
 X
subfo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 0 1
 0
 1 0 0
 0
 1
 X
tlbsync 0 1 1 1 1 1
 0
 ///
 1 0 0 0 1
 1
 0 1 1
 0
 /
 X
 Embedded
lfsux 0 1 1 1 1 1
 frD
 rA
 rB
 1 0 0 0 1
 1
 0 1 1
 1
 /
 X
 FP
lwdx 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 1 0
 0
 0 0 1
 1
 /
 X
 DS
lvtlx 0 1 1 1 1 1
 vD
 rA
 rB
 1 0 0 1 0
 0
 0 1 0
 1
 /
 X
 V
sync 0 1 1 1 1 1
 ///
 L
 /
 ///E
 ///
 1 0 0 1 0
 1
 0 1 1
 0
 /
 X
lfdx 0 1 1 1 1 1
 frD
 rA
 rB
 1 0 0 1 0
 1
 0 1 1
 1
 /
 X
 FP
lfdepx 0 1 1 1 1 1
 frD
 rA
 rB
 1 0 0 1 0
 1
 1 1 1
 1
 /
 X
 E.PD, FP
lddx 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 0 1 1
 0
 0 0 1
 1
 /
 X
 DS, 64
lvswx 0 1 1 1 1 1
 vD
 rA
 rB
 1 0 0 1 1
 0
 0 1 0
 1
 /
 X
 V
nego 0 1 1 1 1 1
 rD
 rA
 ///
 1 0 0 1 1
 0
 1 0 0
 0
 0
 X
nego. 0 1 1 1 1 1
 rD
 rA
 ///
 1 0 0 1 1
 0
 1 0 0
 0
 1
 X
lfdux 0 1 1 1 1 1
 frD
 rA
 rB
 1 0 0 1 1
 1
 0 1 1
 1
 /
 X
 FP
stbdx 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 1 0 0
 0
 0 0 1
 1
 /
 X
 DS
subfeo 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 1 0 0
 0
 1 0 0
 0
 0
 X
subfeo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 1 0 0
 0
 1 0 0
 0
 1
 X
addeo 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 1 0 0
 0
 1 0 1
 0
 0
 X
addeo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 1 0 0
 0
 1 0 1
 0
 1
 X
stdbrx 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 1 0 0
 1
 0 1 0
 0
 /
 X
 64
stwbrx 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 1 0 0
 1
 0 1 1
 0
 /
 X
stfsx 0 1 1 1 1 1
 frS
 rA
 rB
 1 0 1 0 0
 1
 0 1 1
 1
 /
 X
 FP
sthdx 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 1 0 1
 0
 0 0 1
 1
 /
 X
 DS
stvfrx 0 1 1 1 1 1
 vS
 rA
 rB
 1 0 1 0 1
 0
 0 1 0
 1
 /
 X
 V
stbcx. 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 1 0 1
 1
 0 1 1
 0
 1
 X
 ER
stfsux 0 1 1 1 1 1
 frS
 rA
 rB
 1 0 1 0 1
 1
 0 1 1
 1
 /
 X
 FP
stwdx 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 1 1 0
 0
 0 0 1
 1
 /
 X
 DS
stvflx 0 1 1 1 1 1
 vS
 rA
 rB
 1 0 1 1 0
 0
 0 1 0
 1
 /
 X
 V
subfzeo 0 1 1 1 1 1
 rD
 rA
 ///
 1 0 1 1 0
 0
 1 0 0
 0
 0
 X
subfzeo. 0 1 1 1 1 1
 rD
 rA
 ///
 1 0 1 1 0
 0
 1 0 0
 0
 1
 X
addzeo 0 1 1 1 1 1
 rD
 rA
 ///
 1 0 1 1 0
 0
 1 0 1
 0
 0
 X
addzeo. 0 1 1 1 1 1
 rD
 rA
 ///
 1 0 1 1 0
 0
 1 0 1
 0
 1
 X
sthcx. 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 1 1 0
 1
 0 1 1
 0
 1
 X
 ER
stfdx 0 1 1 1 1 1
 frS
 rA
 rB
 1 0 1 1 0
 1
 0 1 1
 1
 /
 X
 FP
stfdepx 0 1 1 1 1 1
 frS
 rA
 rB
 1 0 1 1 0
 1
 1 1 1
 1
 /
 X
 E.PD, FP
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-105
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
stddx 0 1 1 1 1 1
 rS
 rA
 rB
 1 0 1 1 1
 0
 0 0 1
 1
 /
 X
 DS, 64
stvswx 0 1 1 1 1 1
 vS
 rA
 rB
 1 0 1 1 1
 0
 0 1 0
 1
 /
 X
 V
subfmeo 0 1 1 1 1 1
 rD
 rA
 ///
 1 0 1 1 1
 0
 1 0 0
 0
 0
 X
subfmeo. 0 1 1 1 1 1
 rD
 rA
 ///
 1 0 1 1 1
 0
 1 0 0
 0
 1
 X
mulldo 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 1 1 1
 0
 1 0 0
 1
 0
 X
 64
mulldo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 1 1 1
 0
 1 0 0
 1
 1
 X
 64
addmeo 0 1 1 1 1 1
 rD
 rA
 ///
 1 0 1 1 1
 0
 1 0 1
 0
 0
 X
addmeo. 0 1 1 1 1 1
 rD
 rA
 ///
 1 0 1 1 1
 0
 1 0 1
 0
 1
 X
mullwo 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 1 1 1
 0
 1 0 1
 1
 0
 X
mullwo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 0 1 1 1
 0
 1 0 1
 1
 1
 X
dcba 0 1 1 1 1 1
 ///
 0
 rA
 rB
 1 0 1 1 1
 1
 0 1 1
 0
 /
 X
dcbal 0 1 1 1 1 1
 ///
 1
 rA
 rB
 1 0 1 1 1
 1
 0 1 1
 0
 /
 X
 DEO
stfdux 0 1 1 1 1 1
 frS
 rA
 rB
 1 0 1 1 1
 1
 0 1 1
 1
 /
 X
 FP
lvsm 0 1 1 1 1 1
 vD
 rA
 rB
 1 1 0 0 0
 0
 0 1 0
 1
 /
 X
 V
stvepxl 0 1 1 1 1 1
 vS
 rA
 rB
 1 1 0 0 0
 0
 0 1 1
 1
 /
 X
 E.PD, V
addo 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 0 0
 0
 1 0 1
 0
 0
 X
addo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 0 0
 0
 1 0 1
 0
 1
 X
tlbivax 0 1 1 1 1 1
 0
 ///
 rA
 rB
 1 1 0 0 0
 1
 0 0 1
 0
 /
 X
 Embedded
lhbrx 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 0 0
 1
 0 1 1
 0
 /
 X
sraw 0 1 1 1 1 1
 rS
 rA
 rB
 1 1 0 0 0
 1
 1 0 0
 0
 0
 X
sraw. 0 1 1 1 1 1
 rS
 rA
 rB
 1 1 0 0 0
 1
 1 0 0
 0
 1
 X
srad 0 1 1 1 1 1
 rS
 rA
 rB
 1 1 0 0 0
 1
 1 0 1
 0
 0
 X
 64
srad. 0 1 1 1 1 1
 rS
 rA
 rB
 1 1 0 0 0
 1
 1 0 1
 0
 1
 X
 64
evlddepx 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 0 0
 1
 1 1 1
 1
 /
 X
 E.PD, SP
lfddx 0 1 1 1 1 1
 frD
 rA
 rB
 1 1 0 0 1
 0
 0 0 1
 1
 /
 X
 DS, FP
lvtrxl 0 1 1 1 1 1
 vD
 rA
 rB
 1 1 0 0 1
 0
 0 1 0
 1
 /
 X
 V
stvepx 0 1 1 1 1 1
 vS
 rA
 rB
 1 1 0 0 1
 0
 0 1 1
 1
 /
 X
 E.PD, V
mulhus 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 0 1
 0
 1 0 1
 1
 0
 X
 ISAT
mulhus. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 0 1
 0
 1 0 1
 1
 1
 X
 ISAT
dss 0 1 1 1 1 1
 0
 //
 STRM
 ///
 ///
 1 1 0 0 1
 1
 0 1 1
 0
 /
 X
 V
dssall 0 1 1 1 1 1
 1
 //
 STRM
 ///
 ///
 1 1 0 0 1
 1
 0 1 1
 0
 /
 X
 V
srawi 0 1 1 1 1 1
 rS
 rA
 SH
 1 1 0 0 1
 1
 1 0 0
 0
 0
 X
srawi. 0 1 1 1 1 1
 rS
 rA
 SH
 1 1 0 0 1
 1
 1 0 0
 0
 1
 X
sradi 0 1 1 1 1 1
 rS
 rA
 sh1–5
 1 1 0 0 1
 1
 1 0 1 sh0 0
 XS
 64
sradi. 0 1 1 1 1 1
 rS
 rA
 sh1–5
 1 1 0 0 1
 1
 1 0 1 sh0 1
 XS
 64
A-106
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
lvtlxl 0 1 1 1 1 1
 vD
 rA
 rB
 1 1 0 1 0
 0
 0 1 0
 1
 /
 X
 V
subfwu 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 1 0
 0
 1 0 0
 0
 0
 X
 64
subfwu. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 1 0
 0
 1 0 0
 0
 1
 X
 64
addwu 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 1 0
 0
 1 0 1
 0
 0
 X
 64
addwu. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 1 0
 0
 1 0 1
 0
 1
 X
 64
mbar 0 1 1 1 1 1
 MO
 ///
 1 1 0 1 0
 1
 0 1 1
 0
 /
 X
 Embedded
lvswxl 0 1 1 1 1 1
 vD
 rA
 rB
 1 1 0 1 1
 0
 0 1 0
 1
 /
 X
 V
subfwus 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 1 1
 0
 1 0 0
 0
 0
 X
 ISAT
subfwus. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 1 1
 0
 1 0 0
 0
 1
 X
 ISAT
addwus 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 1 1
 0
 1 0 1
 0
 0
 X
 ISAT
addwus. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 1 1
 0
 1 0 1
 0
 1
 X
 ISAT
mulwus 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 1 1
 0
 1 0 1
 1
 0
 X
 ISAT
mulwus. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 0 1 1
 0
 1 0 1
 1
 1
 X
 ISAT
subfhu 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 0
 0
 1 0 0
 0
 0
 X
subfhu. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 0
 0
 1 0 0
 0
 1
 X
addhu 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 0
 0
 1 0 1
 0
 0
 X
addhu. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 0
 0
 1 0 1
 0
 1
 X
divweuo 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 0
 0
 1 0 1
 1
 0
 XO
divweuo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 0
 0
 1 0 1
 1
 1
 XO
tlbsx 0 1 1 1 1 1
 0
 ///
 rA
 rB
 1 1 1 0 0
 1
 0 0 1
 0
 /
 X
 Embedded
sthbrx 0 1 1 1 1 1
 rS
 rA
 rB
 1 1 1 0 0
 1
 0 1 1
 0
 /
 X
extsh 0 1 1 1 1 1
 rS
 rA
 ///
 1 1 1 0 0
 1
 1 0 1
 0
 0
 X
extsh. 0 1 1 1 1 1
 rS
 rA
 ///
 1 1 1 0 0
 1
 1 0 1
 0
 1
 X
evstddepx 0 1 1 1 1 1
 rS
 rA
 rB
 1 1 1 0 0
 1
 1 1 1
 1
 /
 X
 E.PD, SP
stfddx 0 1 1 1 1 1
 frS
 rA
 rB
 1 1 1 0 1
 0
 0 0 1
 1
 /
 X
 DS, FP
stvfrxl 0 1 1 1 1 1
 vS
 rA
 rB
 1 1 1 0 1
 0
 0 1 0
 1
 /
 X
 V
subfhus 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 1
 0
 1 0 0
 0
 0
 X
 ISAT
subfhus. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 1
 0
 1 0 0
 0
 1
 X
 ISAT
addhus 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 1
 0
 1 0 1
 0
 0
 X
 ISAT
addhus. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 1
 0
 1 0 1
 0
 1
 X
 ISAT
divweo 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 1
 0
 1 0 1
 1
 0
 XO
divweo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 0 1
 0
 1 0 1
 1
 1
 XO
tlbre 0 1 1 1 1 1
 0
 ///
 1 1 1 0 1
 1
 0 0 1
 0
 /
 X
 Embedded
extsb 0 1 1 1 1 1
 rS
 rA
 ///
 1 1 1 0 1
 1
 1 0 1
 0
 0
 X
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-107
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
extsb. 0 1 1 1 1 1
 rS
 rA
 ///
 1 1 1 0 1
 1
 1 0 1
 0
 1
 X
stvflxl 0 1 1 1 1 1
 vS
 rA
 rB
 1 1 1 1 0
 0
 0 1 0
 1
 /
 X
 V
subfbu 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 0
 0
 1 0 0
 0
 0
 X
subfbu. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 0
 0
 1 0 0
 0
 1
 X
divduo 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 0
 0
 1 0 0
 1
 0
 X
 64
divduo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 0
 0
 1 0 0
 1
 1
 X
 64
addbu 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 0
 0
 1 0 1
 0
 0
 X
addbu. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 0
 0
 1 0 1
 0
 1
 X
divwuo 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 0
 0
 1 0 1
 1
 0
 X
divwuo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 0
 0
 1 0 1
 1
 1
 X
tlbwe 0 1 1 1 1 1
 0
 ///
 1 1 1 1 0
 1
 0 0 1
 0
 /
 X
 Embedded
icbi 0 1 1 1 1 1
 ///
 rA
 rB
 1 1 1 1 0
 1
 0 1 1
 0
 /
 X
stfiwx 0 1 1 1 1 1
 frS
 rA
 rB
 1 1 1 1 0
 1
 0 1 1
 1
 /
 X
 FP
extsw 0 1 1 1 1 1
 rS
 rA
 ///
 1 1 1 1 0
 1
 1 0 1
 0
 0
 X
 64
extsw. 0 1 1 1 1 1
 rS
 rA
 ///
 1 1 1 1 0
 1
 1 0 1
 0
 1
 X
 64
icbiep 0 1 1 1 1 1
 ///
 rA
 rB
 1 1 1 1 0
 1
 1 1 1
 1
 /
 X
 E>PD
stvswxl 0 1 1 1 1 1
 vS
 rA
 rB
 1 1 1 1 1
 0
 0 1 0
 1
 /
 X
 V
subfbus 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 1
 0
 1 0 0
 0
 0
 X
 ISAT
subfbus. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 1
 0
 1 0 0
 0
 1
 X
 ISAT
divdo 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 1
 0
 1 0 0
 1
 0
 X
 64
divdo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 1
 0
 1 0 0
 1
 1
 X
 64
addbus 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 1
 0
 1 0 1
 0
 0
 X
 ISAT
addbus. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 1
 0
 1 0 1
 0
 1
 X
 ISAT
divwo 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 1
 0
 1 0 1
 1
 0
 X
divwo. 0 1 1 1 1 1
 rD
 rA
 rB
 1 1 1 1 1
 0
 1 0 1
 1
 1
 X
dcbz 0 1 1 1 1 1
 ///
 0
 rA
 rB
 1 1 1 1 1
 1
 0 1 1
 0
 /
 X
dcbzl 0 1 1 1 1 1
 ///
 1
 rA
 rB
 1 1 1 1 1
 1
 0 1 1
 0
 /
 X
 DEO
dcbzep 0 1 1 1 1 1
 ///
 0
 rA
 rB
 1 1 1 1 1
 1
 1 1 1
 1
 /
 X
 E.PD
dcbzlep 0 1 1 1 1 1
 ///
 1
 rA
 rB
 1 1 1 1 1
 1
 1 1 1
 1
 /
 X
 DEO, E.PD
lwz 1 0 0 0 0 0
 rD
 rA
 D
 D
lwzu 1 0 0 0 0 1
 rD
 rA
 D
 D
lbz 1 0 0 0 1 0
 rD
 rA
 D
 D
lbzu 1 0 0 0 1 1
 rD
 rA
 D
 D
stw 1 0 0 1 0 0
 rS
 rA
 D
 D
stwu 1 0 0 1 0 1
 rS
 rA
 D
 D
A-108
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
stb 1 0 0 1 1 0
 rS
 rA
 D
 D
stbu 1 0 0 1 1 1
 rS
 rA
 D
 D
lhz 1 0 1 0 0 0
 rD
 rA
 D
 D
lhzu 1 0 1 0 0 1
 rD
 rA
 D
 D
lha 1 0 1 0 1 0
 rD
 rA
 D
 D
lhau 1 0 1 0 1 1
 rD
 rA
 D
 D
sth 1 0 1 1 0 0
 rS
 rA
 D
 D
sthu 1 0 1 1 0 1
 rS
 rA
 D
 D
lmw 1 0 1 1 1 0
 rD
 rA
 D
 D
stmw 1 0 1 1 1 1
 rS
 rA
 D
 D
lfs 1 1 0 0 0 0
 frD
 rA
 D
 D
 FP
lfsu 1 1 0 0 0 1
 frD
 rA
 D
 D
 FP
lfd 1 1 0 0 1 0
 frD
 rA
 D
 D
 FP
lfdu 1 1 0 0 1 1
 frD
 rA
 D
 D
 FP
stfs 1 1 0 1 0 0
 frS
 rA
 D
 D
 FP
stfsu 1 1 0 1 0 1
 frS
 rA
 D
 D
 FP
stfd 1 1 0 1 1 0
 frS
 rA
 D
 D
 FP
stfdu 1 1 0 1 1 1
 frS
 rA
 D
 D
 FP
ld 1 1 1 0 1 0
 rD
 rA
 DS
 0
 0
 DS
 64
ldu 1 1 1 0 1 0
 rD
 rA
 DS
 0
 1
 DS
 64
lwa 1 1 1 0 1 0
 rD
 rA
 DS
 1
 0
 DS
 64
fdivs 1 1 1 0 1 1
 frD
 frA
 frB
 ///
 1
 0 0 1
 0
 0
 A
 FP
fdivs. 1 1 1 0 1 1
 frD
 frA
 frB
 ///
 1
 0 0 1
 0
 1
 A
 FP.R
fsubs 1 1 1 0 1 1
 frD
 frA
 frB
 ///
 1
 0 1 0
 0
 0
 A
 FP
fsubs. 1 1 1 0 1 1
 frD
 frA
 frB
 ///
 1
 0 1 0
 0
 1
 A
 FP.R
fadds 1 1 1 0 1 1
 frD
 frA
 frB
 ///
 1
 0 1 0
 1
 0
 A
 FP
fadds. 1 1 1 0 1 1
 frD
 frA
 frB
 ///
 1
 0 1 0
 1
 1
 A
 FP.R
fres 1 1 1 0 1 1
 frD
 ///
 frB
 ///
 1
 1 0 0
 0
 0
 A
 FP
fres. 1 1 1 0 1 1
 frD
 ///
 frB
 ///
 1
 1 0 0
 0
 1
 A
 FP.R
fmuls 1 1 1 0 1 1
 frD
 frA
 ///
 frC
 1
 1 0 0
 1
 0
 A
 FP
fmuls. 1 1 1 0 1 1
 frD
 frA
 ///
 frC
 1
 1 0 0
 1
 1
 A
 FP.R
fmsubs 1 1 1 0 1 1
 frD
 frA
 frB
 frC
 1
 1 1 0
 0
 0
 A
 FP
fmsubs. 1 1 1 0 1 1
 frD
 frA
 frB
 frC
 1
 1 1 0
 0
 1
 A
 FP.R
fmadds 1 1 1 0 1 1
 frD
 frA
 frB
 frC
 1
 1 1 0
 1
 0
 A
 FP
fmadds. 1 1 1 0 1 1
 frD
 frA
 frB
 frC
 1
 1 1 0
 1
 1
 A
 FP.R
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
A-109
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
fnmsubs 1 1 1 0 1 1
 frD
 frA
 frB
 frC
 1
 1 1 1
 0
 0
 A
 FP
fnmsubs. 1 1 1 0 1 1
 frD
 frA
 frB
 frC
 1
 1 1 1
 0
 1
 A
 FP.R
fnmadds 1 1 1 0 1 1
 frD
 frA
 frB
 frC
 1
 1 1 1
 1
 0
 A
 FP
fnmadds. 1 1 1 0 1 1
 frD
 frA
 frB
 frC
 1
 1 1 1
 1
 1
 A
 FP.R
std 1 1 1 1 1 0
 rS
 rA
 DS
 0
 0
 DS
 64
stdu 1 1 1 1 1 0
 rS
 rA
 DS
 0
 1
 DS
 64
fcmpu 1 1 1 1 1 1
 crD
 //
 frA
 frB
 0 0 0 0 0
 0
 0 0 0
 0
 /
 X
 FP
frsp 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 0 0 0
 0
 1 1 0
 0
 0
 X
 FP
frsp. 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 0 0 0
 0
 1 1 0
 0
 1
 X
 FP.R
fctiw 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 0 0 0
 0
 1 1 1
 0
 0
 X
 FP
fctiw. 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 0 0 0
 0
 1 1 1
 0
 1
 X
 FP.R
fctiwz 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 0 0 0
 0
 1 1 1
 1
 0
 X
 FP
fctiwz. 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 0 0 0
 0
 1 1 1
 1
 1
 X
 FP.R
fdiv 1 1 1 1 1 1
 frD
 frA
 frB
 ///
 1
 0 0 1
 0
 0
 A
 FP
fdiv. 1 1 1 1 1 1
 frD
 frA
 frB
 ///
 1
 0 0 1
 0
 1
 A
 FP.R
fadd 1 1 1 1 1 1
 frD
 frA
 frB
 ///
 1
 0 1 0
 1
 0
 A
 FP
fsub 1 1 1 1 1 1
 frD
 frA
 frB
 ///
 1
 0 1 0
 0
 0
 A
 FP
fsub. 1 1 1 1 1 1
 frD
 frA
 frB
 ///
 1
 0 1 0
 0
 1
 A
 FP.R
fadd. 1 1 1 1 1 1
 frD
 frA
 frB
 ///
 1
 0 1 0
 1
 1
 A
 FP.R
fsel 1 1 1 1 1 1
 frD
 frA
 frB
 frC
 1
 0 1 1
 1
 0
 A
 FP
fsel. 1 1 1 1 1 1
 frD
 frA
 frB
 frC
 1
 0 1 1
 1
 1
 A
 FP.R
fmul 1 1 1 1 1 1
 frD
 frA
 ///
 frC
 1
 1 0 0
 1
 0
 A
 FP
fmul. 1 1 1 1 1 1
 frD
 frA
 ///
 frC
 1
 1 0 0
 1
 1
 A
 FP.R
frsqrte 1 1 1 1 1 1
 frD
 ///
 frB
 ///
 1
 1 0 1
 0
 0
 A
 FP
frsqrte. 1 1 1 1 1 1
 frD
 ///
 frB
 ///
 1
 1 0 1
 0
 1
 A
 FP.R
fmsub 1 1 1 1 1 1
 frD
 frA
 frB
 frC
 1
 1 1 0
 0
 0
 A
 FP
fmsub. 1 1 1 1 1 1
 frD
 frA
 frB
 frC
 1
 1 1 0
 0
 1
 A
 FP.R
fmadd 1 1 1 1 1 1
 frD
 frA
 frB
 frC
 1
 1 1 0
 1
 0
 A
 FP
fmadd. 1 1 1 1 1 1
 frD
 frA
 frB
 frC
 1
 1 1 0
 1
 1
 A
 FP.R
fnmsub 1 1 1 1 1 1
 frD
 frA
 frB
 frC
 1
 1 1 1
 0
 0
 A
 FP
fnmsub. 1 1 1 1 1 1
 frD
 frA
 frB
 frC
 1
 1 1 1
 0
 1
 A
 FP.R
fnmadd 1 1 1 1 1 1
 frD
 frA
 frB
 frC
 1
 1 1 1
 1
 0
 A
 FP
fnmadd. 1 1 1 1 1 1
 frD
 frA
 frB
 frC
 1
 1 1 1
 1
 1
 A
 FP.R
fcmpo 1 1 1 1 1 1
 crD
 //
 frA
 frB
 0 0 0 0 1
 0
 0 0 0
 0
 /
 X
 FP
mtfsb1 1 1 1 1 1 1
 crbD
 ///
 0 0 0 0 1
 0
 0 1 1
 0
 0
 X
 FP
A-110
EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors, Rev. 1 (EIS 2.1)
Freescale Semiconductor
Instruction Set Listings
Table A-4. Instructions Sorted by Opcode (Binary) (continued)
Mnemonic
 0
 1
 2
 3
 4
 5
 6
 7
 8
 9
 10
 11
 12
 13 14 15 16 17
 18 19 20 21 22
 23 24
 25
 26
 27
 28
 29
 30
 31
 Form Category
mtfsb1. 1 1 1 1 1 1
 crbD
 ///
 0 0 0 0 1
 0
 0 1 1
 0
 1
 X
 FP.R
fneg 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 0 0 1
 0
 1 0 0
 0
 0
 X
 FP
fneg. 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 0 0 1
 0
 1 0 0
 0
 1
 X
 FP.R
mcrfs 1 1 1 1 1 1
 crD
 //
 crfS
 ///
 0 0 0 1 0
 0
 0 0 0
 0
 /
 X
 FP
mtfsb0 1 1 1 1 1 1
 crbD
 ///
 0 0 0 1 0
 0
 0 1 1
 0
 0
 X
 FP
mtfsb0. 1 1 1 1 1 1
 crbD
 ///
 0 0 0 1 0
 0
 0 1 1
 0
 1
 X
 FP.R
fmr 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 0 1 0
 0
 1 0 0
 0
 0
 X
 FP
fmr. 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 0 1 0
 0
 1 0 0
 0
 1
 X
 FP.R
mtfsfi 1 1 1 1 1 1
 crD
 ///
 ///
 W
 IMM
 /
 0 0 1 0 0
 0
 0 1 1
 0
 0
 X
 FP
mtfsfi. 1 1 1 1 1 1
 crD
 ///
 ///
 W
 IMM
 /
 0 0 1 0 0
 0
 0 1 1
 0
 1
 X
 FP.R
fnabs 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 1 0 0
 0
 1 0 0
 0
 0
 X
 FP
fnabs. 1 1 1 1 1 1
 frD
 ///
 frB
 0 0 1 0 0
 0
 1 0 0
 0
 1
 X
 FP.R
fabs 1 1 1 1 1 1
 frD
 ///
 frB
 0 1 0 0 0
 0
 1 0 0
 0
 0
 X
 FP
fabs. 1 1 1 1 1 1
 frD
 ///
 frB
 0 1 0 0 0
 0
 1 0 0
 0
 1
 X
 FP.R
mffs 1 1 1 1 1 1
 frD
 ///
 1 0 0 1 0
 0
 0 1 1
 1
 0
 X
 FP
mffs. 1 1 1 1 1 1
 frD
 ///
 1 0 0 1 0
 0
 0 1 1
 1
 1
 X
 FP.R
mtfsf 1 1 1 1 1 1
 L
 FM
 W
 frB
 1 0 1 1 0
 0
 0 1 1
 1
 0
 XFX FP
mtfsf. 1 1 1 1 1 1
 L
 FM
 W
 frB
 1 0 1 1 0
 0
 0 1 1
 1
 1
 XFX FP.R
fctid 1 1 1 1 1 1
 frD
 ///
 frB
 1 1 0 0 1
 0
 1 1 1
 0
 0
 X
 FP
fctid. 1 1 1 1 1 1
 frD
 ///
 frB
 1 1 0 0 1
 0
 1 1 1
 0
 1
 X
 FP.R
fctidz 1 1 1 1 1 1
 frD
 ///
 frB
 1 1 0 0 1
 0
 1 1 1
 1
 0
 X
 FP
fctidz. 1 1 1 1 1 1
 frD
 ///
 frB
 1 1 0 0 1
 0
 1 1 1
 1
 1
 X
 FP.R
fcfid 1 1 1 1 1 1
 frD
 ///
 frB
 1 1 0 1 0
 0
 1 1 1
 0
 0
 X
 FP
fcfid. 1 1 1 1 1 1
 frD
 ///
 frB
 1 1 0 1 0
 0
 1 1 1
 0
 1
 X
 FP.R'''

def decode(s):
    lines = s.split('\n')
    groups = []
    newgroup = []
    #groups.append(newgroup)

    for line in lines:
        if line.startswith(' '):
            newgroup.append(line)
        elif len(line) == 0:
            newgroup.append(line)
        else:
            newgroup = [ line ]
            groups.append(newgroup)

    return groups

def filterLineGrps(groups):
    dellist = []
    for gidx in range(len(groups)):
        g = groups[gidx]
        if ord(g[0][0]) < 0x60:
            # capital letter, means it's not interesting (headers)
            dellist.append(gidx)

    for x in dellist[::-1]:
        groups.pop(x)


def breakupOpGrps(groups):
    opgroups = {}
    for grp in groups:
        mnem, opgrpidx = grp[0].split(' ', 1)
        grp[0] = opgrpidx
        #grp.insert(0, mnem)

        opgrpidx = int(opgrpidx.replace(' ',''), 2)
        opgrp = opgroups.get(opgrpidx)
        if opgrp == None:
            opgrp = []
            opgroups[opgrpidx] = opgrp

        opgrp.append((mnem, grp))

    return opgroups


def parseData():
    lgrps = decode(encodings)
    filterLineGrps(lgrps)
    opgroups = breakupOpGrps(lgrps)

    return opgroups



''' 
1
d = UIMM * 8
2
 d = UIMM * 4
3
d = UIMM * 2
'''

