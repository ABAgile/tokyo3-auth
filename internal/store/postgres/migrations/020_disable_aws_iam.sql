-- Retire IAM user/group provisioning without deleting integration records
-- or touching AWS resources. Retain config so operators can inspect the old
-- targets and clean up AWS identities and credentials explicitly.
UPDATE app_integrations
SET enabled = FALSE, updated_at = CURRENT_TIMESTAMP
WHERE provider = 'aws_iam' AND enabled = TRUE;
