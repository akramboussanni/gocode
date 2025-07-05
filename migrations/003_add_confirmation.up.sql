ALTER TABLE users
ADD COLUMN email_confirmed BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE users
ADD COLUMN email_confirm_token VARCHAR(64);

ALTER TABLE users
ADD COLUMN email_confirm_issuedat BIGINT;