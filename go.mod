module github.com/wpdlatm2/kms

go 1.26.0

require (
	github.com/cloudflare/circl v1.6.5
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/wpdlatm2/localhsm v0.0.0
)

require (
	github.com/google/go-tpm v0.9.8 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

// Development: the KMIP client lives in the localhsm repository. Remove this line once localhsm's kmip
// package (with lifecycle operations) is pushed and tagged.
replace github.com/wpdlatm2/localhsm => ../localhsm
