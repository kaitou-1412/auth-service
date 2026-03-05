-- name: InsertUserRole :one
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2)
RETURNING *;

-- name: DeleteUserRole :exec
DELETE FROM user_roles
WHERE user_id = $1
  AND role_id = $2;

-- name: GetRolesForUser :many
SELECT r.* FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = $1
ORDER BY r.name;
