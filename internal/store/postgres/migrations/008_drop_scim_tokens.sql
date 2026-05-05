-- Inbound SCIM has been removed. The /scim/v2/* endpoints, the SCIMToken model,
-- and the /admin/scim-tokens APIs are gone; outbound provisioning (auth → vault,
-- auth → IAM, …) replaces all uses. Drop the now-unused token table.
DROP TABLE IF EXISTS scim_tokens;
