CREATE TABLE failed_logins (
    id BIGINT PRIMARY KEY,
    user_id INT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attempted_at BIGINT NOT NULL
);

CREATE INDEX idx_failed_logins_user ON failed_logins(user_id);
CREATE INDEX idx_failed_logins_ip ON failed_logins(ip_address);
CREATE INDEX idx_failed_logins_attempted_at ON failed_logins(attempted_at);

CREATE TABLE lockouts (
    id BIGINT PRIMARY KEY,
    user_id INT NULL,
    ip_address VARCHAR(45) NULL,
    locked_until BIGINT NOT NULL,
    reason VARCHAR(255) NULL,
);

CREATE INDEX idx_lockouts_user ON lockouts(user_id);
CREATE INDEX idx_lockouts_ip ON lockouts(ip_address);
CREATE INDEX idx_lockouts_locked_until ON lockouts(locked_until);
