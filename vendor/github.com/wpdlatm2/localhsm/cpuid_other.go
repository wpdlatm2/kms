//go:build !amd64

package localhsm

func hasSHAExtensions() bool { return false }

func cpuBrand() string { return "" }

func hasVAES() bool       { return false }
func hasVPCLMULQDQ() bool { return false }
