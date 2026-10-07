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
//	gopls       v0.23.0  requires x/tools v0.47.1-0.20260707181000-a299dadba899
//	govulncheck v1.5.0   requires x/tools v0.47.0 (v1.6+ need newer: do not bump alone)
//	staticcheck v0.8.1   requires x/tools v0.44.1-pre
//	deadcode             no version of its own: built from the resolved x/tools
//
// To bump: raise gopls first, then take the newest govulncheck/staticcheck
// whose x/tools requirement is <= gopls's, pin x/tools to gopls's version
// (`go get -tool golang.org/x/tools/cmd/deadcode@<that version>`; an unversioned
// `go get` upgrades x/tools and breaks gopls), and run `make check`.
module github.com/abagile/tokyo3-auth/tools

go 1.26.5

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
	github.com/modelcontextprotocol/go-sdk v1.6.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/exp/typeparams v0.0.0-20260611194520-c48552f49976 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/telemetry v0.0.0-20260625142307-59b4966ccb57 // indirect
	golang.org/x/text v0.38.0 // indirect
	golang.org/x/tools v0.47.1-0.20260707181000-a299dadba899 // indirect
	golang.org/x/tools/gopls v0.23.0 // indirect
	golang.org/x/vuln v1.5.0 // indirect
	honnef.co/go/tools v0.8.1 // indirect
	mvdan.cc/gofumpt v0.10.0 // indirect
	mvdan.cc/xurls/v2 v2.6.0 // indirect
)
