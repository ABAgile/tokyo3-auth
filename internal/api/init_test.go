package api

import (
	creds "github.com/abagile/tokyo3-base/auth/creds"
	"golang.org/x/crypto/bcrypt"
)

// init drops the bcrypt cost for the entire internal/api test suite.
// Default cost 12 takes ~250ms per HashPassword call; this suite runs
// dozens of them across login / registration / password-reset /
// step-up flows, which used to dominate suite runtime.
//
// The security properties the tests assert are about the round trip
// (HashPassword → CheckPassword), the lockout/rotation policy, the
// invalidation flows — none of them depend on the cost value being
// 12 specifically. MinCost (4) is ~1ms, fast enough that bcrypt
// drops out of the test budget.
//
// Production code keeps the default 12; this init only runs in test
// binaries.
func init() {
	creds.BcryptCost = bcrypt.MinCost
}
