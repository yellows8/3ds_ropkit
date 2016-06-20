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
	fi
fi

