ropgadget_patternfinder $1 --script=ropkit_ropgadget_script --baseaddr=0x100000 --patterntype=sha256 --disablelocatehalt
if [[ $? -ne 0 ]]; then
	exit $?
fi

# Locate ROP_LDRR1R1_STRR1R0 here since it's not always available.

printstr=`ropgadget_patternfinder $1 --baseaddr=0x100000 --patterntype=sha256 --patterndata=aa6a623d7c3291340160fd74738249e68b3b4ac2b59cd2c9b5846adcfefb702f --patternsha256size=0xc "--plainout=#define ROP_LDRR1R1_STRR1R0 "`

if [[ $? -eq 0 ]]; then
	echo "$printstr"
fi

# Locate the gadget for ROP_CMPR0R1.

printstr=`ropgadget_patternfinder $1 --baseaddr=0x100000 --patterntype=sha256 --patterndata=947b973f3ad1e3073fa0aaf9e05314cb7f95cb0bbdde1d0f2b65e75c854be08e --patterndatamask=ffffffff00ffffff00ffffffffffffff --patternsha256size=0x10 "--plainout=#define ROP_CMPR0R1 "`
if [[ $? -eq 0 ]]; then
	echo "$printstr"
else
	# This one executes "cmp r0, r1", updates r0 depending on the result, then executes bx-lr.

	printstr=`ropgadget_patternfinder $1 --baseaddr=0x100000 --patterntype=sha256 --patterndata=97b394def410a11df8cc645a58ed647c43aeb17fd0491b3ba336f059be39e74f --patternsha256size=0x14 "--plainout=#define ROP_CMPR0R1_ALT0 "`

	if [[ $? -eq 0 ]]; then
		echo "$printstr"
	else
		echo "//WARNING: ROP_CMPR0R1 not found."
	fi
fi

# Locate the gadget for the conditional throw_fatalerror().

printstr=`ropgadget_patternfinder $1 --baseaddr=0x100000 --patterntype=sha256 --patterndata=871fa0535022597b28d37811aa235ea59f56dd7b02d813c7a3dbc38306efc82b --patterndatamask=ffffffffffffffffffffffffffffffff000000ffffffffff --patternsha256size=0x18 "--plainout=#define ROP_COND_THROWFATALERR "`
if [[ $? -eq 0 ]]; then
	echo "$printstr"
else
	# This one does: r1 = r0_bit31, call throw_fatalerror() when r1 is non-zero. r0 = u32 @ sp+0. Then r3 and pc are popped from stack.

	printstr=`ropgadget_patternfinder $1 --baseaddr=0x100000 --patterntype=sha256 --patterndata=53f02c08f14ce994623440dfa3107c98ce750470d1c68567a353e834cd3aa234 --patterndatamask=ffffffff000000ffffffffffffffffff --patternsha256size=0x10 "--plainout=#define ROP_COND_THROWFATALERR_ALT0 "`

	if [[ $? -eq 0 ]]; then
		echo "$printstr"
	else
		echo "//WARNING: ROP_COND_THROWFATALERR* not found."
	fi
fi

# Locate GXLOW_CMD4.

printstr=`ropgadget_patternfinder $1 --baseaddr=0x100000 --patterntype=sha256 --patterndata=406e130dfe0a99ba64c16ac6ec4a53355cb36f090647b73c5382ea180c88e72c --patternsha256size=0x30 "--plainout=#define GXLOW_CMD4 "`
if [[ $? -eq 0 ]]; then
	echo "$printstr"
else
	printstr=`ropgadget_patternfinder $1 --baseaddr=0x100000 --patterntype=sha256 --patterndata=92aaae0b22699ada29758d0f9c7043897b634196c87c0e6a3c9f562e221d751d --patternsha256size=0x3c "--plainout=#define GXLOW_CMD4 "`

	if [[ $? -eq 0 ]]; then
		echo "$printstr"
	else
		echo "//WARNING: GXLOW_CMD4 not found."
	fi
fi

# Locate IFile_Open.

printstr=`ropgadget_patternfinder $1 --baseaddr=0x100000 --patterntype=sha256 --patterndata=f12b196453c8d76905a0abe3a5395295471ba44f4b1ac6d3fe7f585b59c217ec --patternsha256size=0x18 "--plainout=#define IFile_Open "`
if [[ $? -eq 0 ]]; then
	echo "$printstr"
else
	printstr=`ropgadget_patternfinder $1 --baseaddr=0x100000 --patterntype=sha256 --patterndata=5e4960e460a86bd40ddf00ea5981da01c4ec6246a40d28138976629c4e298fe5 --patternsha256size=0x18 "--plainout=#define IFile_Open "`

	if [[ $? -eq 0 ]]; then
		echo "$printstr"
	else
		echo "//WARNING: IFile_Open not found."
	fi
fi

# Locate IFile_Close.

printstr=`ropgadget_patternfinder $1 --baseaddr=0x100000 --patterntype=sha256 --patterndata=d2dfec7874a22d753a2715e6ad640e0572d6b3d86d12792762d259ff0216705e --patternsha256size=0x18 "--plainout=#define IFile_Close "`
if [[ $? -eq 0 ]]; then
	echo "$printstr"
else
	#If locating the function via the actual function code fails(newer version of that code), try locating it via code calling it instead.

	cmdstr="ropgadget_patternfinder $1 --baseaddr=0x100000 --patterntype=sha256 --patterndata=ca3add997a4d158ec6815506271f20d23d2c1d3a0c33dc85f8ed65e3cfc8d260  --patterndatamask=00fff0ffffffffff000000ff --patternsha256size=0xc --plainout="
	rawaddr=`$cmdstr --addval=0x8`
	tmpdata=`$cmdstr --dataload=0x8`

	if [[ $? -eq 0 ]]; then
		python -c "print \"#define IFile_Close 0x%x\" % ($rawaddr+0x8 + (($tmpdata & 0xffffff)<<2))"
		echo "#define ROP_EQBXLR_NE_CALLVTABLEFUNCPTR (IFile_Close+0x4)" # Offset 0x4 in IFile_Close for ROP conditional execution. For condition-code EQ, bx-lr is executed, otherwise a vtable funcptr call with the r0 object is executed. TODO: move this into the macros file later once that file is created?
	else
		echo "//WARNING: IFile_Close not found."
	fi
fi

