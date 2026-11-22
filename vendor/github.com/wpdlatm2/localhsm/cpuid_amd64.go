//go:build amd64

package localhsm

func cpuidRaw(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)

// hasSHAExtensions reports the x86 SHA-NI instructions (CPUID.(EAX=7,ECX=0):EBX[29]).
func hasSHAExtensions() bool {
	if maxLeaf, _, _, _ := cpuidRaw(0, 0); maxLeaf < 7 {
		return false
	}
	_, ebx, _, _ := cpuidRaw(7, 0)
	return ebx&(1<<29) != 0
}

// cpuBrand reads the processor brand string (CPUID leaves 0x80000002-4).
func cpuBrand() string {
	if max, _, _, _ := cpuidRaw(0x80000000, 0); max < 0x80000004 {
		return ""
	}
	var b []byte
	for leaf := uint32(0x80000002); leaf <= 0x80000004; leaf++ {
		a, bb, c, d := cpuidRaw(leaf, 0)
		for _, r := range [4]uint32{a, bb, c, d} {
			b = append(b, byte(r), byte(r>>8), byte(r>>16), byte(r>>24))
		}
	}
	for len(b) > 0 && (b[len(b)-1] == 0 || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return string(b)
}

// leaf7ECX returns CPUID.(EAX=7,ECX=0):ECX (0 if unsupported).
func leaf7ECX() uint32 {
	if maxLeaf, _, _, _ := cpuidRaw(0, 0); maxLeaf < 7 {
		return 0
	}
	_, _, ecx, _ := cpuidRaw(7, 0)
	return ecx
}

// hasVAES: vector AES (256/512-bit AES instructions), ECX[9]. Present on CPUs without AVX-512 too.
func hasVAES() bool { return leaf7ECX()&(1<<9) != 0 }

// hasVPCLMULQDQ: vector carry-less multiply, ECX[10].
func hasVPCLMULQDQ() bool { return leaf7ECX()&(1<<10) != 0 }
