module github.com/t0ul/GORED

go 1.27.1

replace (
	github.com/t0ul/gledger => ../gledger
	github.com/t0ul/goflage => ../goflage
	github.com/t0ul/gorauder => ../gorauder
	github.com/t0ul/goserve => ../goserve
)

require (
	github.com/t0ul/gledger v0.0.0-00010101000000-000000000000
	github.com/t0ul/goflage v0.0.0-00010101000000-000000000000
	github.com/t0ul/goserve v0.0.0-00010101000000-000000000000
	modernc.org/sqlite v1.60.1
)

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
