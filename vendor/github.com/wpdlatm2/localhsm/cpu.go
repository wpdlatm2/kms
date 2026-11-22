package localhsm

import (
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/sys/cpu"
)

// CPUFeatures lists the CPU instruction-set extensions that accelerate cryptography.
// Go's standard library uses them automatically (AES-NI + PCLMULQDQ for AES-GCM, SHA-NI for SHA-256,
// ARMv8 AES/PMULL/SHA2 on arm64); this reports whether they are present, so a deployment can verify
// that it will not silently fall back to slow software code (typical cause: a VM or container CPU
// model that hides the flags).
type CPUFeatures struct {
	Arch  string
	Model string

	// x86
	AES, PCLMULQDQ, SHA, AVX2, AVX512F, RDRAND, RDSEED bool
	VAES, VPCLMULQDQ                                   bool // 256/512-bit wide AES / carry-less multiply
	// arm64
	ARMAES, PMULL, ARMSHA1, ARMSHA2, ARMSHA512 bool
}

// DetectCPU inspects the running CPU. (The GODEBUG=cpu.<feature>=off switches of the Go runtime are
// honored, which is how the benchmark tool simulates a CPU without acceleration.)
func DetectCPU() CPUFeatures {
	f := CPUFeatures{Arch: runtime.GOARCH, Model: strings.TrimSpace(cpuBrand())}
	switch runtime.GOARCH {
	case "amd64", "386":
		x := cpu.X86
		f.AES, f.PCLMULQDQ, f.AVX2, f.AVX512F = x.HasAES, x.HasPCLMULQDQ, x.HasAVX2, x.HasAVX512F
		f.RDRAND, f.RDSEED = x.HasRDRAND, x.HasRDSEED
		f.VAES, f.VPCLMULQDQ = hasVAES(), hasVPCLMULQDQ()
		f.SHA = hasSHAExtensions() && !godebugOff("sha")
	case "arm64":
		a := cpu.ARM64
		f.ARMAES, f.PMULL, f.ARMSHA1, f.ARMSHA2, f.ARMSHA512 = a.HasAES, a.HasPMULL, a.HasSHA1, a.HasSHA2, a.HasSHA512
	}
	return f
}

// AESAccelerated: hardware AES and the carry-less multiply that AES-GCM's GHASH needs.
func (f CPUFeatures) AESAccelerated() bool {
	return (f.AES && f.PCLMULQDQ) || (f.ARMAES && f.PMULL)
}

// SHAAccelerated: hardware SHA-256 instructions.
func (f CPUFeatures) SHAAccelerated() bool { return f.SHA || f.ARMSHA2 }

// Summary is a one-line, human-readable description.
func (f CPUFeatures) Summary() string {
	var on []string
	add := func(ok bool, n string) {
		if ok {
			on = append(on, n)
		}
	}
	add(f.AES, "AES-NI")
	add(f.PCLMULQDQ, "PCLMULQDQ")
	add(f.SHA, "SHA-NI")
	add(f.VAES, "VAES")
	add(f.VPCLMULQDQ, "VPCLMULQDQ")
	add(f.AVX2, "AVX2")
	add(f.AVX512F, "AVX-512")
	add(f.RDRAND, "RDRAND")
	add(f.RDSEED, "RDSEED")
	add(f.ARMAES, "ARM-AES")
	add(f.PMULL, "PMULL")
	add(f.ARMSHA1, "SHA1")
	add(f.ARMSHA2, "SHA2")
	add(f.ARMSHA512, "SHA512")
	if len(on) == 0 {
		on = []string{"(none)"}
	}
	return fmt.Sprintf("%s %q: %s; AES-GCM accelerated=%v, SHA-256 accelerated=%v",
		f.Arch, f.Model, strings.Join(on, " "), f.AESAccelerated(), f.SHAAccelerated())
}

// godebugOff reports whether GODEBUG contains cpu.<name>=off.
func godebugOff(name string) bool {
	for _, kv := range strings.Split(getenv("GODEBUG"), ",") {
		if strings.TrimSpace(kv) == "cpu."+name+"=off" {
			return true
		}
	}
	return false
}
