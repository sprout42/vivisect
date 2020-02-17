import sys
import unittest
import vivisect
import envi.archs.ppc
import vivisect.symboliks.analysis as vs_anal

MARGIN_OF_ERROR = 200

class PpcInstructionSet(unittest.TestCase):
    def getVivEnv(self, arch='ppc'):
        vw = vivisect.VivWorkspace()
        vw.setMeta("Architecture", arch)
        vw.addMemoryMap(0, 7, 'firmware', '\xff' * 16384*1024)
        vw.addMemoryMap(0xbfb00000, 7, 'firmware', '\xfe' * 16384*1024)

        emu = vw.getEmulator()
        emu.setMeta('forrealz', True)
        emu.logread = emu.logwrite = True

        sctx = vs_anal.getSymbolikAnalysisContext(vw)
        return vw, emu, sctx

    def test_envi_ppcvle_disasm(self):
        test_pass = 0

        vw, emu, sctx = self.getVivEnv('vle')
        
        import ppc_vle_instructions
        for test_bytes, result_instr in ppc_vle_instructions.instructions:
            try:
                op = vw.arch.archParseOpcode(test_bytes.decode('hex'), 0)
                op_str = repr(op).strip()
                if op_str == result_instr:
                    test_pass += 1
                if result_instr != op_str:
                    print ('{}: ours: {} != {}'.format(test_bytes, op_str, result_instr))
            except Exception, e:
                print ('ERROR: {}: {}'.format(test_bytes, result_instr))
                sys.excepthook(*sys.exc_info())

        print "test_envi_ppcvle_disasm: %d of %d successes" % (test_pass, len(ppc_vle_instructions.instructions))
        self.assertAlmostEqual(test_pass, len(ppc_vle_instructions.instructions), delta=MARGIN_OF_ERROR)

    def test_envi_ppc_server_disasm(self):
        test_pass = 0

        vw, emu, sctx = self.getVivEnv('ppc-server')

        import ppc_server_instructions
        for test_bytes, result_instr in ppc_server_instructions.instructions:
            try:
                op = vw.arch.archParseOpcode(test_bytes.decode('hex'), 0)
                op_str = repr(op).strip()
                if op_str == result_instr:
                    test_pass += 1
                if result_instr != op_str:
                    print ('{}: ours: {} != {}'.format(test_bytes, op_str, result_instr))
            except Exception, e:
                print ('ERROR: {}: {}'.format(test_bytes, result_instr))
                sys.excepthook(*sys.exc_info())

        print "test_envi_ppc_server_disasm: %d of %d successes" % (test_pass, len(ppc_server_instructions.instructions))
        self.assertAlmostEqual(test_pass, len(ppc_server_instructions.instructions), delta=MARGIN_OF_ERROR)

    def test_MASK_and_ROTL32(self):
        import envi.archs.ppc.emu as eape
        import vivisect.symboliks.archs.ppc as vsap

        for x in range(64):
            for y in range(64):
                #mask = 
                emumask = eape.MASK(x, y)

                symmask = vsap.MASK(vsap.Const(x, 8), vsap.Const(y, 8))
                #print hex(emumask), repr(symmask), symmask


                self.assertEqual(emumask, symmask.solve(), 'MASK({}, {}): {} != {}'.format(x, y, emumask, symmask.solve()))

        for y in range(32):
            emurot32 = eape.ROTL32(0x31337040, y)
            symrot32 = vsap.ROTL32(vsap.Const(0x31337040, 8), vsap.Const(y, 8))
            self.assertEqual(emurot32, symrot32.solve(), 'ROTL32(0x31337040, {}): {} != {}   {}'.format(y, hex(emurot32), hex(symrot32.solve()), symrot32))

        for y in range(64):
            emurot64 = eape.ROTL64(0x31337040, y)
            symrot64 = vsap.ROTL64(vsap.Const(0x31337040, 8), vsap.Const(y, 8))
            self.assertEqual(emurot64, symrot64.solve(), 'ROTL64(0x31337040, {}): {} != {}   {}'.format(y, hex(emurot64), hex(symrot64.solve()), symrot64))

    def test_CR_and_XER(self):
        OPCODE_ADDCO = '7C620C15'.decode('hex')

        vw, emu, sctx = self.getVivEnv(arch='ppc-server')
        ppcarch = vw.imem_archs[0]
        op = ppcarch.archParseOpcode(OPCODE_ADDCO)
        self._do_CR_XER(op, emu, 1, 2, 0, 0, 0, 3, 0x40000000, 0)
        self._do_CR_XER(op, emu, 0x3FFFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFFF, 0, 0, 0, 0x7ffffffffffffffeL, 0x40000000L, 0)
        self._do_CR_XER(op, emu, 0x4000000000000000, 0x4000000000000000, 0, 0, 0xc0000000, 0x8000000000000000, 0x90000000, 0xc0000000L)
        self._do_CR_XER(op, emu, 0x4000000000000000, 0x4000000000000000, 0, 0, 0, 0x8000000000000000, 0x90000000, 0xc0000000)
        self._do_CR_XER(op, emu, 0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF, 0, 0, 0, 0xfffffffffffffffe, 0x90000000, 0xc0000000)
        self._do_CR_XER(op, emu, 0x8000000000000000, 0x8000000000000000, 0, 0, 0, 0, 0x30000000, 0xe0000000)
        self._do_CR_XER(op, emu, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0xfffffffffffffffe, 0x90000000, 0xa0000000)
        self._do_CR_XER(op, emu, 1, 2, 0, 0, 0xa0000000, 3, 0x40000000, 0)

    def _do_CR_XER(self, op, emu, r1, r2, r3, cr, xer, expr3, expcr, expxer):
        emu.setRegisterByName('r1', r1)
        emu.setRegisterByName('r2', r2)
        emu.setRegisterByName('r3', r3)
        emu.setRegisterByName('CR', cr)
        emu.setRegisterByName('XER', xer)

        emu.executeOpcode(op)

        newcr = emu.getRegisterByName('CR')
        newxer = emu.getRegisterByName('XER')
        newr3 = emu.getRegisterByName('r3')

        self.assertEqual((repr(op), r1, r2, r3, cr, xer, newr3, newcr, newxer), (repr(op), r1, r2, r3, cr, xer, expr3, expcr, expxer))

