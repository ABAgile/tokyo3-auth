package api

import (
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/abagile/tokyo3-base/ratelimit"
)

// Default per-IP request budgets (requests/minute; burst equals the rate).
//
// Interactive credential endpoints (password, MFA code, registration, device
// user-code entry) get a tight budget: legitimate users need a handful of
// requests, while credential stuffing and code guessing need many.
//
// Machine endpoints (/token, /revoke, /device_authorization) get a larger
// one: relying-party backends exchange codes for every user from a single
// egress IP, so a tight limit would throttle legitimate sign-ins while still
// bounding client-secret guessing.
const (
	defaultAuthRatePerMin  = 20
	defaultTokenRatePerMin = 120
)

// privateRanges are loopback and RFC 1918/4193 blocks. X-Forwarded-For is
// honoured for rate-limit keying only when the immediate peer is inside one of
// these (or an operator-supplied extra), i.e. the request came through a
// local reverse proxy such as the Traefik edge.
var privateRanges = func() []*net.IPNet {
	var out []*net.IPNet
	for _, s := range []string{
		"127.0.0.0/8", "::1/128",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"fc00::/7",
	} {
		_, cidr, _ := net.ParseCIDR(s)
		out = append(out, cidr)
	}
	return out
}()

// newLimiter builds a per-IP limiter for ratePerMin (<=0 selects def).
func newLimiter(ratePerMin, def int, proxies []*net.IPNet, log *slog.Logger) *ratelimit.Limiter {
	if ratePerMin <= 0 {
		ratePerMin = def
	}
	return ratelimit.New(ratelimit.Config{
		RPS:            float64(ratePerMin) / 60.0,
		Burst:          ratePerMin,
		TrustedProxies: proxies,
		Log:            log,
		OnThrottle:     throttled,
	})
}

// throttled renders a 429. Browsers (form posts) get plain text; API clients
// get the same JSON error envelope as the rest of the API. Retry-After is
// already set by the limiter.
func throttled(w http.ResponseWriter, r *http.Request) {
	const msg = "too many requests; try again later"
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Error(w, msg, http.StatusTooManyRequests)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":"too_many_requests","error_description":"` + msg + `"}` + "\n"))
}

// limitAuth applies the interactive-credential limiter to one route.
func (s *Server) limitAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.authLimiter.Middleware(next).ServeHTTP
}

// limitToken applies the machine-endpoint limiter to one route.
func (s *Server) limitToken(next http.HandlerFunc) http.HandlerFunc {
	return s.tokenLimiter.Middleware(next).ServeHTTP
}

// mergeProxies returns the built-in private ranges plus operator extras.
func mergeProxies(extra []*net.IPNet) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(privateRanges)+len(extra))
	out = append(out, privateRanges...)
	return append(out, extra...)
}
