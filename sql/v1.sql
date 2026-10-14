CREATE TABLE users (
       id UUID PRIMARY KEY,
       email VARCHAR(320) NOT NULL,
       password_hash VARCHAR(255) NOT NULL,
       status VARCHAR(30) NOT NULL,

       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
       updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

       CONSTRAINT uk_users_email UNIQUE (email)
);