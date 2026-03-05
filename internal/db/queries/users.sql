-- name: CreateUser :one
INSERT INTO users (app_id, email, password_hash)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetUser :one
SELECT * FROM users
WHERE id = $1
LIMIT 1;

-- name: GetUserPasswordHash :one
SELECT password_hash FROM users
WHERE id = $1
LIMIT 1;

-- name: UpdateUserPasswordHash :one
UPDATE users
SET password_hash = $2
WHERE id = $1
RETURNING *;

-- name: GetUserByAppAndEmail :one
SELECT * FROM users
WHERE app_id = $1
  AND email = $2
LIMIT 1;
