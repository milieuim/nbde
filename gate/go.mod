module github.com/milieuim/nbde/gate

go 1.26.7

require (
	github.com/anatol/tang.go v0.0.0-20260314012254-926d9c91008f
	github.com/lestrrat-go/jwx/v3 v3.0.13
	golang.org/x/crypto v0.59.0
	golang.org/x/sys v0.50.0
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.0.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.4 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
)

// Audit fixes not yet upstream: github.com/oluceps/tang.go, branch fix/audit-findings.
replace github.com/anatol/tang.go => github.com/oluceps/tang.go v0.0.0-20261117071618-3d1daf796034
