import Elf

import vtrace.formats.base as v_fmt_base
import envi.symstore.resolver as e_resolv

class ElfTrace(v_fmt_base.TraceFormat):

    def _fmt_init(self):
        self.setMeta('format','elf')

    def _fmt_parselib(self, filename, baseaddr, normname):
        typemap = {
            Elf.STT_FUNC:e_resolv.FunctionSymbol,
            Elf.STT_SECTION:e_resolv.SectionSymbol,
        }

        fd = self._wire_openfile(filename)
        elf = Elf.Elf(fd)
        addbase = 0
        if not elf.isPreLinked() and elf.isSharedObject():
            addbase = baseaddr

        for sec in elf.sections:
            sym = e_resolv.SectionSymbol(sec.name, sec.sh_addr+addbase, sec.sh_size, normname)
            self.addSymbol(sym)

        for sym in elf.symbols:
            symclass = typemap.get((sym.st_info & 0xf), e_resolv.Symbol)
            sym = symclass(sym.name, sym.st_value+addbase, sym.st_size, normname)
            self.addSymbol(sym)

        for sym in elf.dynamic_symbols:
            symclass = typemap.get((sym.st_info & 0xf), e_resolv.Symbol)
            sym = symclass(sym.name, sym.st_value+addbase, sym.st_size, normname)
            self.addSymbol(sym)

        if elf.isExecutable():
            sym = e_resolv.Symbol('__entry', elf.e_entry, 0, normname)
            self.addSymbol(sym)
