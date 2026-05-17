-- Make sessions.user_id nullable so machine-credential sessions
-- (issued by the /token client_credentials grant) can be stored
-- without violating the FK to users(id).
ALTER TABLE sessions ALTER COLUMN user_id DROP NOT NULL;
