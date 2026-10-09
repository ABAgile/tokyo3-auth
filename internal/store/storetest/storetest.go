// Package storetest is the behavioural contract every store.Store
// implementation must satisfy. Each backend's tests call Run with a factory
// returning a fresh, fully migrated, empty store; the same assertions then
// run against SQLite and PostgreSQL so the two cannot drift apart.
package storetest

import (
	"slices"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// Factory returns a fresh, migrated, empty store, registering any cleanup
// (close, drop database) on t.
type Factory func(t *testing.T) store.Store

// Run executes the full contract against stores built by newStore.
func Run(t *testing.T, newStore Factory) {
	t.Helper()
	for name, fn := range map[string]func(*testing.T, Factory){
		"UserRoundTrip":                        testUserRoundTrip,
		"ClientArrayRoundTrip":                 testClientArrayRoundTrip,
		"PortalClientSeed":                     testPortalClientSeed,
		"ExternalIDsUpsert":                    testExternalIDsUpsert,
		"GroupMembersIdempotent":               testGroupMembersIdempotent,
		"GrantRoundTrip":                       testGrantRoundTrip,
		"GrantDeleteExpired":                   testGrantDeleteExpired,
		"GrantSingleUseUnderConcurrency":       testGrantSingleUseUnderConcurrency,
		"SessionLifecycle":                     testSessionLifecycle,
		"RefreshRotationUnderConcurrency":      testRefreshRotationUnderConcurrency,
		"SessionsByUserBulkDelete":             testSessionsByUserBulkDelete,
		"SessionDeleteExpired":                 testSessionDeleteExpired,
		"TOTPLifecycle":                        testTOTPLifecycle,
		"WebAuthnCredentialLifecycle":          testWebAuthnCredentialLifecycle,
		"WebAuthnSessionLifecycle":             testWebAuthnSessionLifecycle,
		"SigningKeyLifecycle":                  testSigningKeyLifecycle,
		"IntegrationLifecycle":                 testIntegrationLifecycle,
		"ExternalIDDelete":                     testExternalIDDelete,
		"UserUpdatePaths":                      testUserUpdatePaths,
		"UserConflictsAndNotFound":             testUserConflictsAndNotFound,
		"ClientUpdateSecretAndDelete":          testClientUpdateSecretAndDelete,
		"GroupUpdateAndRemove":                 testGroupUpdateAndRemove,
		"ListPortalClientsForUser":             testListPortalClientsForUser,
		"ListPortalClientsNoDuplicates":        testListPortalClientsForUserNoDuplicatesOnMultipleGroupMatch,
		"ReplaceClientVisibilityRemovesPrior":  testReplaceClientVisibilityRemovesPriorRows,
		"AWSAccountCRUD":                       testAWSAccountCRUD,
		"AWSRoleCRUDAndCascade":                testAWSRoleCRUDAndCascadeOnAccount,
		"ListAWSRolesForUser":                  testListAWSRolesForUser,
		"AWSRevokedUsersIdempotentListAndReap": testAWSRevokedUsersAddIsIdempotentListAndReap,
		"RetiredRefreshTokens":                 testRetiredRefreshTokens,
		"AuthTimeRoundTrip":                    testAuthTimeRoundTrip,
		"ExpiryIgnoresLocalZone":               testExpiryIgnoresLocalZone,
		"EmptyScopesRoundTrip":                 testEmptyScopesRoundTrip,
		"DeviceGrantLifecycle":                 testDeviceGrantLifecycle,
	} {
		t.Run(name, func(t *testing.T) { fn(t, newStore) })
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func tileIDs(cs []*model.Client) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}

func contains(ids []uuid.UUID, target uuid.UUID) bool { return slices.Contains(ids, target) }
