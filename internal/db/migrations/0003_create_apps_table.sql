-- +goose Up
CREATE TABLE apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_apps_updated_at
BEFORE UPDATE ON apps
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_apps_name ON apps(name);

-- +goose Down
DROP TRIGGER IF EXISTS update_apps_updated_at ON apps;
DROP INDEX IF EXISTS idx_apps_name;
DROP TABLE IF EXISTS apps;