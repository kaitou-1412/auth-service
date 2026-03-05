-- name: CreateSession :one
INSERT INTO sessions (user_id, device_info, ip_address, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: RevokeSession :one
UPDATE sessions
SET revoked = TRUE
WHERE id = $1
RETURNING *;

-- name: RevokeAllSessionsForUser :exec
UPDATE sessions
SET revoked = TRUE
WHERE user_id = $1
  AND revoked = FALSE;

-- name: VerifySession :one
SELECT * FROM sessions
WHERE id = $1
  AND revoked = FALSE
  AND expires_at > NOW()
LIMIT 1;

-- name: GetSessionsForUser :many
SELECT * FROM sessions
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: VerifySessionBelongsToUser :one
SELECT * FROM sessions
WHERE id = $1
  AND user_id = $2
LIMIT 1;
