ropgadget_patternfinder $1 --script=ropkit_ropgadget_script --baseaddr=0x100000 --patterntype=sha256 --disablelocatehalt
if [[ $? -ne 0 ]]; then
	exit $?
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

