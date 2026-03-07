-- name: GetRole :one
SELECT * FROM roles
WHERE id = $1
LIMIT 1;
