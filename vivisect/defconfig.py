import vdb
import getpass


defconfig = {
    'viv':{

        'SymbolCacheSave':True,

        'parsers':{
            'pe':{
                'loadresources':False,
                'carvepes':True,
                'nx':False,
            },
            'elf':{
            },
            'blob':{
                'arch':'',
                'bigend':False,
                'baseaddr':0x20200000,
            },
            'macho':{
                'baseaddr':0x70700000,
                'fatarch':'',
            },
            'ihex':{
                'arch':'',
                'bigend':False,
                'offset':0,
            },
            'vbf':{
                'arch':'',
                'bigend':False,
            },
            'srec':{
                'arch':'',
                'bigend':False,
                'offset':0,
            },
        },

        'analysis':{
            'pointertables':{
                'table_min_len':4,
            },
            'stack':{
                'base': 0x40078000,
                'mask': 0xFFFF8000,
                'top': 0x40080000,
                'pointer': 0x4007ffe0,
        },
            'taint':{
                'base': 0xbfb0000f,
                'byte': 'a',
                'offset': 0x1000,
                'mask': 0xffffe000,
            },
        },

        'remote':{
            'wait_for_plat_arch': 10,
        },

        'arch':{
            'ppc':{
                'options':'spe',
                'bootstrap':{
                    'rchwaddrs':[
                        0x0000, 0x4000, 0x10000, 0x1C000, 0x20000, 0x30000,
                        0x800000
                    ],
                },
                'findvlepages':True,
                'mmu':[],
            },
        },
    },
    'cli':vdb.defconfig.get('cli'), # FIXME make our own...
    'vdb':vdb.defconfig.get('vdb'),
    'user':{
        'name': getpass.getuser(),
    }
}

defconfig.get('cli').update(vdb.defconfig.get('cli'))

# Config elements docs
docconfig = {

    'viv':{

        'SymbolCacheSave':'Save vivisect names to the vdb configured symbol cache?',

        'parsers':{
            'pe':{
                'loadresources':'Should we load resource segments?',
                'carvepes':'Should we carve pes?',
                'nx':'Should we truly treat sections that dont execute as non executable?'
            },
            'elf':{
            },
            'blob':{
                'arch':'What architecture is the blob?',
                'baseaddr':'Base virtual address for loading the blob.',
            },
            'macho':{
                'baseaddr':'Base virtual address for loading the macho',
                'fatarch':'Which architecture binary to extract from a FAT macho',
            },
            'ihex':{
                'arch':'What architecture is the ihex dump?',
                'bigend':'Is the architecture Big-Endian (MSB)?',
            },
            'srec':{
                'arch':'What architecture is the srec dump?',
                'offset':'Skip over initial bytes in the file',
            },
        },

        'analysis':{
            'pointertables':{
                'table_min_len':'How many pointers must be in a row to make a table?',
            },
            'stack':{
                'base':'Stack base address',
                'mask':'Stack mask',
                'top':'Stack top address',
                'pointer':'Stack pointer',
        },
            'taint':{
                'base':'Taint base address',
                'byte':'Taint byte value',
                'offset':'Taint VA offset',
                'mask':'Taint mask',
            },
        },

        'arch':{
            'ppc':{
                'options':'PowerPC processor features to enable',
                'bootstrap':{
                    'rchwaddrs':'A list of addresses to look for at for the reset-control half word (RCHW) used for PowerPC boot target identification',
                },
                'findvlepages':'Flag to search and automatically add VLE memory map pages from MMU instructions',
                'mmu':'A list of [<address>, <size>] values that indicate memory segments where PowerPC VLE instructions can be found',
            },
        },

    },

    'vdb':vdb.docconfig.get('vdb'),
    'user':{
        'name': 'Username.  When not set, defaults to current system user.',
        }
}
