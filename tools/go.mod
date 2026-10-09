// Pinned developer tools (staticcheck, gopls, govulncheck, deadcode), run via
// `go tool -modfile=tools/go.mod <name>` from the repository root (see the
// Makefile). Kept in its own module so none of this reaches the app's go.mod
// or govulncheck's view of it.
//
// ALIGNMENT RULE: gopls and deadcode are built from golang.org/x/tools, and
// gopls only compiles against the x/tools snapshot it was released with. Go
// resolves x/tools to the highest version any tool requires, so every tool
// here must require x/tools no newer than gopls's. Today:
//
//	gopls       v0.24.0-pre.2  requires x/tools v0.51.1-0.20261007173519-d3cf2258b6cf
//	govulncheck v1.8.0         requires x/tools v0.50.0
//	staticcheck v0.8.1         requires x/tools v0.44.1-pre
//	deadcode                   no version of its own: built from the resolved x/tools
//
// The set must also be new enough for the Go toolchain in use: staticcheck
// reads compiler export data through x/tools, and an x/tools older than the
// toolchain fails with "export data version N is greater than maximum
// supported version" (seen going from Go 1.27.1 to 1.27.2 with the previous
// pins: gopls v0.23.0, govulncheck v1.5.0). gopls has no stable release past
// v0.23.0 yet; move to v0.24.0 when it ships.
//
// To bump: raise gopls first, then take the newest govulncheck/staticcheck
// whose x/tools requirement is <= gopls's, pin x/tools to gopls's version
// (`go get -tool golang.org/x/tools/cmd/deadcode@<that version>`; an unversioned
// `go get` upgrades x/tools and breaks gopls), and run `make check`.
module github.com/abagile/tokyo3-auth/tools

go 1.27.0

tool (
	golang.org/x/tools/cmd/deadcode
	golang.org/x/tools/gopls
	golang.org/x/vuln/cmd/govulncheck
	honnef.co/go/tools/cmd/staticcheck
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/fatih/camelcase v1.0.0 // indirect
	github.com/fatih/gomodifytags v1.17.1-0.20250423142747-f3939df9aa3c // indirect
	github.com/fatih/structtag v1.2.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/modelcontextprotocol/go-sdk v1.8.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/exp/typeparams v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/telemetry v0.0.0-20260924152758-ed294f943157 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.org/x/tools v0.51.1-0.20261007173519-d3cf2258b6cf // indirect
	golang.org/x/tools/gopls v0.24.0-pre.2 // indirect
	golang.org/x/vuln v1.8.0 // indirect
	honnef.co/go/tools v0.8.1 // indirect
	mvdan.cc/gofumpt v0.12.0 // indirect
	mvdan.cc/xurls/v2 v2.6.0 // indirect
)
