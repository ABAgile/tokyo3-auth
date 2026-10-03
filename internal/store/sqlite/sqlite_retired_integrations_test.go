package sqlite

import (
	"context"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/google/uuid"
)

func TestMigrationDisablesOnlyRetiredIAMIntegrations(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	rows := []*model.AppIntegration{
		{ID: uuid.New(), Name: "legacy-enabled", Provider: "aws_iam", Enabled: true},
		{ID: uuid.New(), Name: "legacy-disabled", Provider: "aws_iam", Enabled: false},
		{ID: uuid.New(), Name: "scim", Provider: model.AppIntegrationProviderSCIM, Enabled: true},
		{ID: uuid.New(), Name: "federation", Provider: model.AppIntegrationProviderAWSFederation, Enabled: true},
	}
	for _, row := range rows {
		if err := db.CreateIntegration(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	const legacyConfig = `{"group_map":{"Engineering":"legacy-iam-group"}}`
	if _, err := db.db.Exec(`UPDATE app_integrations SET config = ? WHERE id = ?`, legacyConfig, rows[0].ID); err != nil {
		t.Fatal(err)
	}

	// Recreate an upgrade from 019: the retirement migration initially ran
	// against an empty table, so removing its marker restores that state.
	if _, err := db.db.Exec(`DELETE FROM schema_migrations WHERE version = '020_disable_aws_iam.sql'`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := db.migrate(); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			got, err := db.GetIntegration(ctx, row.ID)
			if err != nil {
				t.Fatalf("migration deleted %q: %v", row.Name, err)
			}
			wantEnabled := row.Provider != "aws_iam"
			if got.Enabled != wantEnabled || got.Provider != row.Provider || got.Name != row.Name {
				t.Errorf("migration changed the wrong fields: %+v", got)
			}
		}
		var config string
		if err := db.db.QueryRow(`SELECT config FROM app_integrations WHERE id = ?`, rows[0].ID).Scan(&config); err != nil {
			t.Fatal(err)
		}
		if config != legacyConfig {
			t.Errorf("legacy config was not retained: %q", config)
		}
		enabled, err := db.ListEnabledIntegrations(ctx)
		if err != nil || len(enabled) != 2 {
			t.Fatalf("enabled integrations = %v, error = %v; want only SCIM and federation", enabled, err)
		}
	}
}
