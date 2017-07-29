import envi
import vivisect
import vivisect.parsers as v_parsers
from vivisect.const import *

archcalls = {
    'i386':'cdecl',
    'amd64':'sysvamd64call',
    'arm':'armcall',
    }


def parseFd(vw, fd, filename=None):
    fd.seek(0)
    arch = vw.config.viv.parsers.blob.arch
    bigend = vw.config.viv.parsers.blob.bigend
    baseaddr = vw.config.viv.parsers.blob.baseaddr
    try:
        envi.getArchModule(arch)
    except Exception, e:
        raise Exception('Blob loader *requires* arch option (-O viv.parsers.blob.arch="<archname>")')

    vw.setMeta('Architecture', arch)
    vw.setMeta('Platform','unknown')
    vw.setMeta('Format','blob')

    vw.setMeta('bigend', bigend)
    vw.setMeta('DefaultCall', archcalls.get(arch,'unknown'))

    bytez =  fd.read() 
    bytearry = parse9bitBytes(bytez)
    vw.addMemoryMap(baseaddr, 7, filename, bytearry)
    vw.addSegment( baseaddr, len(bytez), '%.8x' % baseaddr, 'blob' )

def parse9bitBytes(bytez):
    off = 0
    boff = 0
    out = []
    try:
        while True:
            byte9 = (ord(bytez[off]) <<(1+boff)) & 0x1ff
            byte9 |= (ord(bytez[off+1]) >> (7-boff)) & 0x1ff
            out.append(byte9)

            boff += 1
            if boff > 7:
                boff = 0
                off += 1
            off += 1
    except Exception,e:
        print e
    out.append(byte9)

    return out
    
def parseFile(vw, filename):

    arch = vw.config.viv.parsers.blob.arch
    bigend = vw.config.viv.parsers.blob.bigend
    baseaddr = vw.config.viv.parsers.blob.baseaddr

    try:
        envi.getArchModule(arch)
    except Exception, e:
        raise Exception('Blob loader *requires* arch option (-O viv.parsers.blob.arch="<archname>")')


    vw.setMeta('Architecture', arch)
    vw.setMeta('Platform','unknown')
    vw.setMeta('Format','blob')

    vw.setMeta('bigend', bigend)
    vw.setMeta('DefaultCall', archcalls.get(arch,'unknown'))

    fname = vw.addFile(filename, baseaddr, v_parsers.md5File(filename))
    bytez =  file(filename, "rb").read()
    bytearry = parse9bitBytes(bytez)
    vw.addMemoryMap(baseaddr, 7, filename, bytearry)
    vw.addSegment( baseaddr, len(bytez), '%.8x' % baseaddr, 'blob' )


def parseMemory(vw, memobj, baseaddr):
    va,size,perms,fname = memobj.getMemoryMap(baseaddr)
    if not fname:
        fname = 'map_%.8x' % baseaddr
    bytes = memobj.readMemory(va, size)
    fname = vw.addFile(fname, baseaddr, v_parsers.md5Bytes(bytes))
    vw.addMemoryMap(va, perms, fname, bytes)
    vw.setMeta('DefaultCall', archcalls.get(arch,'unknown'))

