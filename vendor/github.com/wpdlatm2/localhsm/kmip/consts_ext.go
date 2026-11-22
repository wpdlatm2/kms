package kmip

// Algorithm identifiers beyond KMIP 1.4/2.0, with the values Eviden (Cosmian) KMS uses. They are not part
// of the specification data the generated constants come from.
const (
	AlgMLKEM512  uint32 = 0x00000039
	AlgMLKEM768  uint32 = 0x0000003A
	AlgMLKEM1024 uint32 = 0x0000003B
	AlgMLDSA44   uint32 = 0x0000003C
	AlgMLDSA65   uint32 = 0x0000003D
	AlgMLDSA87   uint32 = 0x0000003E

	AlgSLHDSASHA2128s  uint32 = 0x0000003F
	AlgSLHDSASHA2128f  uint32 = 0x00000040
	AlgSLHDSASHA2192s  uint32 = 0x00000041
	AlgSLHDSASHA2192f  uint32 = 0x00000042
	AlgSLHDSASHA2256s  uint32 = 0x00000043
	AlgSLHDSASHA2256f  uint32 = 0x00000044
	AlgSLHDSASHAKE128s uint32 = 0x00000045
	AlgSLHDSASHAKE128f uint32 = 0x00000046
	AlgSLHDSASHAKE192s uint32 = 0x00000047
	AlgSLHDSASHAKE192f uint32 = 0x00000048
	AlgSLHDSASHAKE256s uint32 = 0x00000049
	AlgSLHDSASHAKE256f uint32 = 0x0000004A

	// vendor extensions (0x8880_xxxx)
	AlgConfigurableKEM uint32 = 0x88800003
	AlgCoverCrypt      uint32 = 0x88800004
	AlgX25519MLKEM768  uint32 = 0x88800006
	AlgX448MLKEM1024   uint32 = 0x88800007

	// recommended-curve extensions (0x8000_xxxx)
	CurveEd25519 uint32 = 0x80000001
	CurveEd448   uint32 = 0x80000002
	CurveX25519  uint32 = 0x80000003 // pqc-kms extension (not in Eviden KMS)
	CurveX448    uint32 = 0x80000004 // pqc-kms extension

	// AlgXWing is a pqc-kms vendor extension (X-Wing hybrid KEM).
	AlgXWing uint32 = 0x88800010
)

// Cryptographic Usage Mask bits added after KMIP 1.4.
const (
	UsageAuthenticate int32 = 0x100000
	UsageUnrestricted int32 = 0x200000
)

// extAlgorithmNames names the algorithms of this file (the generated map covers the specification).
var extAlgorithmNames = map[uint32]string{
	AlgMLKEM512: "ML-KEM-512", AlgMLKEM768: "ML-KEM-768", AlgMLKEM1024: "ML-KEM-1024",
	AlgMLDSA44: "ML-DSA-44", AlgMLDSA65: "ML-DSA-65", AlgMLDSA87: "ML-DSA-87",
	AlgSLHDSASHA2128s: "SLH-DSA-SHA2-128s", AlgSLHDSASHA2128f: "SLH-DSA-SHA2-128f",
	AlgSLHDSASHA2192s: "SLH-DSA-SHA2-192s", AlgSLHDSASHA2192f: "SLH-DSA-SHA2-192f",
	AlgSLHDSASHA2256s: "SLH-DSA-SHA2-256s", AlgSLHDSASHA2256f: "SLH-DSA-SHA2-256f",
	AlgSLHDSASHAKE128s: "SLH-DSA-SHAKE-128s", AlgSLHDSASHAKE128f: "SLH-DSA-SHAKE-128f",
	AlgSLHDSASHAKE192s: "SLH-DSA-SHAKE-192s", AlgSLHDSASHAKE192f: "SLH-DSA-SHAKE-192f",
	AlgSLHDSASHAKE256s: "SLH-DSA-SHAKE-256s", AlgSLHDSASHAKE256f: "SLH-DSA-SHAKE-256f",
	AlgConfigurableKEM: "ConfigurableKEM", AlgCoverCrypt: "Covercrypt",
	AlgX25519MLKEM768: "X25519MLKEM768", AlgX448MLKEM1024: "X448MLKEM1024", AlgXWing: "X-Wing",
}
