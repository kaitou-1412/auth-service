-- name: RevokeRefreshToken :one
UPDATE refresh_tokens
SET revoked = TRUE
WHERE id = $1
RETURNING *;

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (session_id, user_id, token_hash, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: RevokeRefreshTokensForSession :exec
UPDATE refresh_tokens
SET revoked = TRUE
WHERE session_id = $1
  AND revoked = FALSE;

-- name: RevokeAllRefreshTokensForUser :exec
UPDATE refresh_tokens
SET revoked = TRUE
WHERE user_id = $1
  AND revoked = FALSE;

-- name: FindRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token_hash = $1
  AND revoked = FALSE
  AND expires_at > NOW()
LIMIT 1;
