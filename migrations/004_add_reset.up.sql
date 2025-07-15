ALTER TABLE users
ADD COLUMN password_reset_token VARCHAR(64);

ALTER TABLE users
ADD COLUMN password_reset_issuedat BIGINT;