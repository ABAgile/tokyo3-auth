package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
)

func TestParseAWSRegions(t *testing.T) {
	tests := []struct {
		name, list, def string
		wantRegions     []string
		wantDef         string
		wantErr         string
	}{
		{"both empty", "", "", nil, "", ""},
		{"comma and space separated, deduped", "ap-east-2, eu-west-1 ap-east-2", "", []string{"ap-east-2", "eu-west-1"}, "", ""},
		{"default already listed", "ap-east-2,eu-west-1", "eu-west-1", []string{"ap-east-2", "eu-west-1"}, "eu-west-1", ""},
		{"default added when missing", "ap-east-2", "eu-west-1", []string{"ap-east-2", "eu-west-1"}, "eu-west-1", ""},
		{"default alone", "", "eu-west-1", []string{"eu-west-1"}, "eu-west-1", ""},
		{"bad list entry", "ap-east-2,evil.com/x", "", nil, "", "AUTHD_AWS_REGIONS"},
		{"bad default", "", "EU-WEST-1", nil, "", "AUTHD_AWS_DEFAULT_REGION"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			regions, def, err := ParseAWSRegions(tc.list, tc.def)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(regions, tc.wantRegions) || def != tc.wantDef {
				t.Errorf("got (%v, %q), want (%v, %q)", regions, def, tc.wantRegions, tc.wantDef)
			}
		})
	}
}

func TestAWSRegionOptions(t *testing.T) {
	roleWith := func(regions ...string) *model.AWSRole { return &model.AWSRole{AllowedRegions: regions} }
	tests := []struct {
		name    string
		regions []string
		def     string
		role    *model.AWSRole
		want    []regionOption
	}{
		{"unconfigured renders no dropdown", nil, "", nil, nil},
		{"no default: global first and selected", []string{"ap-east-2"}, "", nil, []regionOption{
			{Value: "", Label: "Global (default)", Selected: true},
			{Value: "ap-east-2", Label: "ap-east-2"},
		}},
		{"default region replaces global", []string{"ap-east-2", "eu-west-1"}, "eu-west-1", nil, []regionOption{
			{Value: "ap-east-2", Label: "ap-east-2"},
			{Value: "eu-west-1", Label: "eu-west-1 (default)", Selected: true},
		}},
		{"role without restriction inherits the list", []string{"ap-east-2", "eu-west-1"}, "", roleWith(), []regionOption{
			{Value: "", Label: "Global (default)", Selected: true},
			{Value: "ap-east-2", Label: "ap-east-2"},
			{Value: "eu-west-1", Label: "eu-west-1"},
		}},
		{"restricted role drops global, first eligible is default", []string{"ap-east-2", "eu-west-1"}, "", roleWith("eu-west-1"), []regionOption{
			{Value: "eu-west-1", Label: "eu-west-1 (default)", Selected: true},
		}},
		{"restricted role keeps default region when allowed", []string{"ap-east-2", "eu-west-1"}, "eu-west-1", roleWith("ap-east-2", "eu-west-1"), []regionOption{
			{Value: "ap-east-2", Label: "ap-east-2"},
			{Value: "eu-west-1", Label: "eu-west-1 (default)", Selected: true},
		}},
		{"restricted role without the default region picks its first", []string{"ap-east-2", "eu-west-1"}, "eu-west-1", roleWith("ap-east-2"), []regionOption{
			{Value: "ap-east-2", Label: "ap-east-2 (default)", Selected: true},
		}},
		{"role entries outside the list are ignored", []string{"ap-east-2"}, "", roleWith("ap-east-2", "us-west-2"), []regionOption{
			{Value: "ap-east-2", Label: "ap-east-2 (default)", Selected: true},
		}},
		{"restriction with nothing eligible yields none", []string{"ap-east-2"}, "", roleWith("us-west-2"), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{awsRegions: tc.regions, awsDefaultRegion: tc.def}
			if got := s.awsRegionOptions(tc.role); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("awsRegionOptions() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestAWSRegionsBlocked(t *testing.T) {
	restricted := &model.AWSRole{AllowedRegions: []string{"us-west-2"}}
	if !(&Server{awsRegions: []string{"ap-east-2"}}).awsRegionsBlocked(restricted) {
		t.Error("role restricted to an unlisted region must be blocked")
	}
	if (&Server{}).awsRegionsBlocked(restricted) {
		t.Error("with AUTHD_AWS_REGIONS unset nothing is blocked")
	}
	if (&Server{awsRegions: []string{"ap-east-2"}}).awsRegionsBlocked(nil) {
		t.Error("unrestricted role must not be blocked")
	}
}

func TestResolveAWSRegion(t *testing.T) {
	roleWith := func(regions ...string) *model.AWSRole { return &model.AWSRole{AllowedRegions: regions} }
	tests := []struct {
		name      string
		regions   []string
		def       string
		role      *model.AWSRole
		requested string
		want      string
		wantOK    bool
	}{
		{"unconfigured, empty is global", nil, "", nil, "", "", true},
		{"unconfigured, any region rejected", nil, "", nil, "ap-east-2", "", false},
		{"listed region accepted", []string{"ap-east-2"}, "", nil, "ap-east-2", "ap-east-2", true},
		{"unlisted region rejected", []string{"ap-east-2"}, "", nil, "eu-west-1", "", false},
		{"empty with no default is global", []string{"ap-east-2"}, "", nil, "", "", true},
		{"empty maps to default region", []string{"ap-east-2"}, "ap-east-2", nil, "", "ap-east-2", true},
		{"role allows its region", []string{"ap-east-2", "eu-west-1"}, "", roleWith("eu-west-1"), "eu-west-1", "eu-west-1", true},
		{"role rejects a listed region it excludes", []string{"ap-east-2", "eu-west-1"}, "", roleWith("eu-west-1"), "ap-east-2", "", false},
		{"restricted role: empty maps to its first region, not global", []string{"ap-east-2", "eu-west-1"}, "", roleWith("eu-west-1"), "", "eu-west-1", true},
		{"restricted role with nothing eligible rejects empty", []string{"ap-east-2"}, "", roleWith("us-west-2"), "", "", false},
		{"restricted role with nothing eligible rejects all", []string{"ap-east-2"}, "", roleWith("us-west-2"), "ap-east-2", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{awsRegions: tc.regions, awsDefaultRegion: tc.def}
			got, ok := s.resolveAWSRegion(tc.role, tc.requested)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("resolveAWSRegion(%q) = (%q, %v), want (%q, %v)", tc.requested, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestPortalHome_RendersRegionDropdown(t *testing.T) {
	r := newTestRig(t)
	r.server.awsRegions = []string{"ap-east-2", "eu-west-1"}
	r.server.awsDefaultRegion = "eu-west-1"
	u := seedTestUser(t, r.store, "home@example.com", "H0m3Reg!onP@ss")
	cookie, _ := loginPortal(t, r, "home@example.com", "H0m3Reg!onP@ss")
	role := seedAWSCatalog(t, r, u, "region-tile", false)

	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+"/portal", nil)
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	for _, want := range []string{
		`<select id="region-` + role.ID.String() + `" name="region">`,
		`<option value="ap-east-2">ap-east-2</option>`,
		`<option value="eu-west-1" selected>eu-west-1 (default)</option>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("home page missing %q", want)
		}
	}
	if strings.Contains(body, `<option value="">`) {
		t.Error("global option must not be offered when a default region is configured")
	}
}

func TestPortalHome_NoRegionsKeepsSingleButton(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "plain@example.com", "Pl@inRegionP4ss")
	cookie, _ := loginPortal(t, r, "plain@example.com", "Pl@inRegionP4ss")
	seedAWSCatalog(t, r, u, "plain-tile", false)

	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+"/portal", nil)
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	if !strings.Contains(body, "Open AWS Console") {
		t.Error("home page missing the Open AWS Console button")
	}
	if strings.Contains(body, `name="region"`) {
		t.Error("no region control expected when AUTHD_AWS_REGIONS is unset")
	}
}

func TestAWSConsole_RejectsUnlistedRegion(t *testing.T) {
	r := newTestRig(t)
	r.server.awsRegions = []string{"ap-east-2"}
	u := seedTestUser(t, r.store, "reg@example.com", "R3gionRejectP@ss")
	cookie, _ := loginPortal(t, r, "reg@example.com", "R3gionRejectP@ss")
	// Step-up role: the rejection must come before the MFA bounce.
	role := seedAWSCatalog(t, r, u, "region-reject", true)

	form := url.Values{"role_id": {role.ID.String()}, "region": {"eu-west-1"}}
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/portal/aws/console", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/portal/aws?error=region+not+available") {
		t.Errorf("Location = %q, want region-not-available error", loc)
	}
}

// The step-up handler reads region from its own request, so
// buildAWSConsoleURL must refuse an unlisted one itself.
func TestBuildAWSConsoleURL_RejectsUnlistedRegion(t *testing.T) {
	r := newTestRig(t)
	r.server.awsRegions = []string{"ap-east-2"}
	u := seedTestUser(t, r.store, "bld@example.com", "Bu1ldRegionP@ss")
	_, sess := loginPortal(t, r, "bld@example.com", "Bu1ldRegionP@ss")
	role := seedAWSCatalog(t, r, u, "region-build", false)

	req := httptest.NewRequest(http.MethodPost, "/portal/step-up", nil)
	_, err := r.server.buildAWSConsoleURL(req, &portalCtx{User: u, Session: sess}, role, "eu-west-1")
	if err == nil || !strings.Contains(err.Error(), "region not available") {
		t.Fatalf("err = %v, want region not available", err)
	}
}

func TestPortalHome_RestrictedRoleTiles(t *testing.T) {
	r := newTestRig(t)
	r.server.awsRegions = []string{"ap-east-2", "eu-west-1"}
	u := seedTestUser(t, r.store, "restr@example.com", "R3strictedP@ss1")
	cookie, _ := loginPortal(t, r, "restr@example.com", "R3strictedP@ss1")
	role := seedAWSCatalog(t, r, u, "restricted-tile", false)
	role.AllowedRegions = []string{"eu-west-1"}
	if err := r.store.UpdateAWSRole(t.Context(), role); err != nil {
		t.Fatalf("UpdateAWSRole: %v", err)
	}

	get := func() string {
		req, _ := http.NewRequest(http.MethodGet, r.srv.URL+"/portal", nil)
		resp := doRequest(t, req, cookie)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	body := get()
	if !strings.Contains(body, `<option value="eu-west-1" selected>eu-west-1 (default)</option>`) ||
		strings.Contains(body, `value="ap-east-2"`) || strings.Contains(body, `<option value="">`) {
		t.Errorf("restricted tile should offer only eu-west-1:\n%s", body)
	}

	role.AllowedRegions = []string{"us-west-2"} // not in the server-wide list
	if err := r.store.UpdateAWSRole(t.Context(), role); err != nil {
		t.Fatalf("UpdateAWSRole: %v", err)
	}
	body = get()
	if !strings.Contains(body, "No console region is available") || strings.Contains(body, "Open AWS Console") {
		t.Error("tile with no eligible region must be blocked")
	}
}

func TestAWSConsole_RejectsRegionOutsideRoleRestriction(t *testing.T) {
	r := newTestRig(t)
	r.server.awsRegions = []string{"ap-east-2", "eu-west-1"}
	u := seedTestUser(t, r.store, "narrow@example.com", "N@rrowRegionP4ss")
	cookie, _ := loginPortal(t, r, "narrow@example.com", "N@rrowRegionP4ss")
	role := seedAWSCatalog(t, r, u, "narrow-role", false)
	role.AllowedRegions = []string{"eu-west-1"}
	if err := r.store.UpdateAWSRole(t.Context(), role); err != nil {
		t.Fatalf("UpdateAWSRole: %v", err)
	}

	// ap-east-2 is in the global list but excluded for this role.
	form := url.Values{"role_id": {role.ID.String()}, "region": {"ap-east-2"}}
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/portal/aws/console", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/portal/aws?error=region+not+available") {
		t.Errorf("Location = %q, want region-not-available error", loc)
	}
}

func TestAdminAWSRoleRegions(t *testing.T) {
	r := newTestRig(t)
	r.server.awsRegions = []string{"ap-east-2", "eu-west-1"}
	cookie := seedAdminPortalCookie(t, r, "regadmin@example.com")
	u := seedTestUser(t, r.store, "owner@example.com", "0wnerRegionP@ss1")
	role := seedAWSCatalog(t, r, u, "admin-regions", false)

	post := func(regions string) string {
		form := url.Values{"allowed_regions": {regions}}
		req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/portal/admin/aws/roles/"+role.ID.String()+"/regions", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp := doRequest(t, req, cookie)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want 302", resp.StatusCode)
		}
		return resp.Header.Get("Location")
	}
	stored := func() []string {
		got, err := r.store.GetAWSRole(t.Context(), role.ID)
		if err != nil {
			t.Fatalf("GetAWSRole: %v", err)
		}
		return got.AllowedRegions
	}

	if loc := post("eu-west-1, eu-west-1"); !strings.Contains(loc, "success=") {
		t.Errorf("Location = %q, want success", loc)
	}
	if got := stored(); !reflect.DeepEqual(got, []string{"eu-west-1"}) {
		t.Errorf("stored = %v, want [eu-west-1]", got)
	}
	// A role may only narrow the server-wide list, never widen it.
	if loc := post("us-west-2"); !strings.Contains(loc, "error=") {
		t.Errorf("Location = %q, want error for unlisted region", loc)
	}
	if got := stored(); !reflect.DeepEqual(got, []string{"eu-west-1"}) {
		t.Errorf("rejected update changed stored regions to %v", got)
	}
	if loc := post(""); !strings.Contains(loc, "success=") {
		t.Errorf("Location = %q, want success on clear", loc)
	}
	if got := stored(); len(got) != 0 {
		t.Errorf("stored after clear = %v, want empty", got)
	}
}
