module github.com/t0ul/GORED

go 1.27.1

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.48.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

require (
	github.com/t0ul/ADD v0.0.0-20261011220314-cc0309da3b1a
	github.com/t0ul/gledger v0.0.0-20261012043634-e291a2255ec6
	github.com/t0ul/gobrig v0.0.0
	github.com/t0ul/goflage v0.0.0-20261009135357-739ce25ed7e2
	github.com/t0ul/gorauder v0.0.0-20261011215148-7e0b43d5947e
	github.com/t0ul/goserve v0.0.0-20261011215800-ced3cd4c6cce
	modernc.org/sqlite v1.60.1
)

// gobrig (the contained-detonation chamber) is a sibling fleet module; the brigagent cmd
// imports its pure package (Client/DiscoverRCE/RCEFinding), never its cgo launcher.
replace github.com/t0ul/gobrig => ../gobrig
