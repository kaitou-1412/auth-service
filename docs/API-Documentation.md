# Auth Service API Documentation

Base URL: `/v1`

---

## Health Check

### `GET /v1/health`

Returns the health status of the service.

**Authentication:** None

**Response:**

- `200 OK`

```json
{
  "status": "ok"
}
```

---

# Authentication Endpoints

## Signup

### `POST /v1/auth/signup`

Registers a new user for a given app.

**Authentication:** None

**Request Body:**

| Field      | Type   | Required | Description                    |
|------------|--------|----------|--------------------------------|
| `app_id`   | string | Yes      | UUID of the app to register under |
| `email`    | string | Yes      | Valid email address            |
| `password` | string | Yes      | User password (see rules below)|

**Password Rules:**

- 8-128 characters long
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character
- No leading or trailing spaces

**Validations (in order):**

1. All fields (`app_id`, `email`, `password`) must be present and non-empty.
2. `app_id` must be a valid UUID format.
3. App with the given `app_id` must exist in the database.
4. `email` must be a valid email address (parsed via RFC 5322).
5. `password` must satisfy all password rules above.
6. The email must not already be registered for the given app.

**Business Logic:**

- Password is hashed using bcrypt (default cost) before storage.
- A new user record is created with `is_active = true` and `email_verified = false` by default (database defaults).

**Response:**

- `201 Created`

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "app_id": "00000000-0000-0000-0000-000000000001",
  "email": "user@example.com",
  "is_active": true,
  "email_verified": false,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

**Errors:**

| Status | Condition                        | Error Message                                  |
|--------|----------------------------------|------------------------------------------------|
| 400    | Missing required fields          | `app_id, email, and password are required`     |
| 400    | Invalid UUID format for app_id   | `invalid app_id`                               |
| 400    | Invalid email format             | `invalid email address`                        |
| 400    | Password too short/long          | `password must be 8-128 characters`            |
| 400    | Password missing character types | `password must contain at least one uppercase letter, one lowercase letter, one number, and one special character` |
| 400    | Password has leading/trailing spaces | `password must not have leading or trailing spaces` |
| 404    | App not found in DB              | `app not found`                                |
| 409    | Email already registered for app | `email already registered for this app`        |
| 500    | Internal error                   | `internal server error`                        |

---

## Login

### `POST /v1/auth/login`

Authenticates a user and returns access and refresh tokens.

**Authentication:** None

**Request Body:**

| Field      | Type   | Required | Description                    |
|------------|--------|----------|--------------------------------|
| `app_id`   | string | Yes      | UUID of the app                |
| `email`    | string | Yes      | Valid email address            |
| `password` | string | Yes      | User password                  |

**Validations (in order):**

1. All fields (`app_id`, `email`, `password`) must be present and non-empty.
2. `app_id` must be a valid UUID format.
3. App with the given `app_id` must exist in the database.
4. `email` must be a valid email address (parsed via RFC 5322).

**Business Logic:**

1. Looks up the user by `app_id` + `email`. Returns `invalid email or password` if not found.
2. Checks if the user is active. Returns `invalid email or password` if inactive.
3. Verifies the password against the stored bcrypt hash. Returns `invalid email or password` if wrong.
4. Creates a new session (24h expiry) with the caller's `User-Agent` and IP address.
5. Generates a cryptographically random refresh token (32 bytes), stores its SHA-256 hash (30-day expiry).
6. Generates a JWT access token (RS256, 15-minute expiry) with claims:
   - `sub`: user ID (hex-encoded UUID)
   - `session_id`: session ID (hex-encoded UUID)
   - `iat`: issued-at timestamp
   - `exp`: expiration timestamp

**Response:**

- `200 OK`

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "hex-encoded-random-token"
}
```

**Errors:**

| Status | Condition                        | Error Message                                  |
|--------|----------------------------------|------------------------------------------------|
| 400    | Missing required fields          | `app_id, email, and password are required`     |
| 400    | Invalid UUID format for app_id   | `invalid app_id`                               |
| 400    | Invalid email format             | `invalid email address`                        |
| 404    | App not found in DB              | `app not found`                                |
| 401    | Wrong email/password or inactive | `invalid email or password`                    |
| 500    | Internal error                   | `internal server error`                        |

---

# Token Management

## Refresh Token

### `POST /v1/auth/token/refresh`

Rotates the refresh token and issues a new access token.

**Authentication:** None

**Request Body:**

| Field           | Type   | Required | Description                |
|-----------------|--------|----------|----------------------------|
| `refresh_token` | string | Yes      | Current valid refresh token |

**Business Logic:**

1. Finds the refresh token by its SHA-256 hash. Must not be revoked and must not be expired.
2. Verifies the associated session is not revoked and not expired.
3. Revokes the old refresh token (sets `revoked = true`).
4. Creates a new refresh token linked to the same session and user.
5. Generates a new JWT access token (RS256, 15-minute expiry).

**Response:**

- `200 OK`

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "hex-encoded-new-token",
  "expires_in": 900,
  "token_type": "Bearer"
}
```

**Errors:**

| Status | Condition                        | Error Message                              |
|--------|----------------------------------|--------------------------------------------|
| 401    | Token not found, revoked, or expired | `refresh token not found or expired`   |
| 401    | Session revoked                  | `session has been revoked`                 |
| 401    | Session expired                  | `session has expired`                      |
| 500    | Internal error                   | `internal server error`                    |

---

# Logout

## Logout Current Session

### `POST /v1/auth/logout`

Revokes the current session and its associated refresh tokens.

**Authentication:** Required (Bearer token in `Authorization` header)

**Request Body:** None

**Headers:**

| Header          | Required | Description                          |
|-----------------|----------|--------------------------------------|
| `Authorization` | Yes      | `Bearer <access_token>`             |

**Business Logic:**

1. The session ID is extracted from the JWT access token (set by the auth middleware).
2. All refresh tokens associated with the session are revoked.
3. The session itself is revoked.

**Response:**

- `200 OK`

```json
{
  "message": "logged out successfully"
}
```

**Errors:**

| Status | Condition                    | Error Message                   |
|--------|------------------------------|---------------------------------|
| 401    | Missing/invalid/expired token| `missing authorization header` / `invalid or expired token` |
| 400    | Invalid session ID           | `invalid session_id`            |
| 500    | Internal error               | `internal server error`         |

---

## Logout All Devices

### `POST /v1/auth/logout-all`

Logs the user out from all devices by revoking all sessions and refresh tokens.

**Authentication:** Required (Bearer token in `Authorization` header)

**Request Body:** None

**Headers:**

| Header          | Required | Description              |
|-----------------|----------|--------------------------|
| `Authorization` | Yes      | `Bearer <access_token>` |

**Business Logic:**

1. The user ID is extracted from the JWT access token (set by the auth middleware).
2. All sessions for the user are revoked (`revoked = true`).
3. All refresh tokens for the user are revoked (`revoked = true`).

**Response:**

- `200 OK`

```json
{
  "message": "logged out from all devices"
}
```

**Errors:**

| Status | Condition                    | Error Message                   |
|--------|------------------------------|---------------------------------|
| 401    | Missing/invalid/expired token| `missing authorization header` / `invalid or expired token` |
| 500    | Internal error               | `internal server error`         |

---

# Session Management

## List Sessions

### `GET /v1/auth/sessions`

Returns all active (non-revoked) sessions for the authenticated user.

**Authentication:** Required (Bearer token in `Authorization` header)

**Request Body:** None

**Headers:**

| Header          | Required | Description              |
|-----------------|----------|--------------------------|
| `Authorization` | Yes      | `Bearer <access_token>` |

**Business Logic:**

1. The user ID is extracted from the JWT access token.
2. Fetches all non-revoked sessions for the user, sorted by `created_at DESC`.
3. The session matching the current `session_id` from the token is marked with `"current": true`.

**Response:**

- `200 OK`

```json
{
  "sessions": [
    {
      "session_id": "6b3dcb20-8e0c-4e3f-aef2-0d61c4f27d3e",
      "device_info": "MacBook Pro",
      "ip_address": "103.21.45.90",
      "created_at": "2026-03-05T12:10:00Z",
      "expires_at": "2026-03-12T12:10:00Z",
      "revoked": false,
      "current": true
    },
    {
      "session_id": "c91c90e6-3df4-42d0-8c51-d54df4bcac1b",
      "device_info": "iPhone 14",
      "ip_address": "49.207.18.210",
      "created_at": "2026-03-01T09:22:11Z",
      "expires_at": "2026-03-08T09:22:11Z",
      "revoked": false,
      "current": false
    }
  ]
}
```

**Errors:**

| Status | Condition                    | Error Message                   |
|--------|------------------------------|---------------------------------|
| 401    | Missing/invalid/expired token| `missing authorization header` / `invalid or expired token` |
| 500    | Internal error               | `internal server error`         |

---

## Revoke Session

### `DELETE /v1/auth/sessions/{session_id}`

Revokes a specific session and its associated refresh tokens. Allows a user to log out a specific device.

**Authentication:** Required (Bearer token in `Authorization` header)

**Path Parameters:**

| Parameter    | Type   | Description                    |
|--------------|--------|--------------------------------|
| `session_id` | string | UUID of the session to revoke |

**Headers:**

| Header          | Required | Description              |
|-----------------|----------|--------------------------|
| `Authorization` | Yes      | `Bearer <access_token>` |

**Business Logic:**

1. Verifies the session belongs to the authenticated user.
2. Revokes the session (`revoked = true`).
3. Revokes all refresh tokens associated with the session.

**Response:**

- `200 OK`

```json
{
  "message": "session revoked successfully"
}
```

**Errors:**

| Status | Condition                       | Error Message                            |
|--------|---------------------------------|------------------------------------------|
| 400    | Invalid session_id format       | `invalid session_id`                     |
| 401    | Missing/invalid/expired token   | `missing authorization header` / `invalid or expired token` |
| 403    | Session belongs to another user | `session does not belong to this user`   |
| 404    | Session not found               | `session not found`                      |
| 500    | Internal error                  | `internal server error`                  |

---

# Password Management

## Change Password

### `POST /v1/auth/password/change`

Changes the password for the authenticated user. Revokes all existing sessions and refresh tokens after the change.

**Authentication:** Required (Bearer token in `Authorization` header)

**Headers:**

| Header          | Required | Description              |
|-----------------|----------|--------------------------|
| `Authorization` | Yes      | `Bearer <access_token>` |

**Request Body:**

| Field              | Type   | Required | Description                     |
|--------------------|--------|----------|---------------------------------|
| `current_password` | string | Yes      | The user's current password     |
| `new_password`     | string | Yes      | The new password (same rules as signup) |

**Business Logic:**

1. Fetches the current password hash for the authenticated user.
2. Verifies `current_password` against the stored bcrypt hash.
3. Validates `new_password` against the same password rules as signup (8-128 chars, uppercase, lowercase, digit, special char, no leading/trailing spaces).
4. Hashes the new password with bcrypt and updates the user record.
5. Revokes all sessions for the user (`revoked = true`).
6. Revokes all refresh tokens for the user (`revoked = true`).

**Response:**

- `200 OK`

```json
{
  "message": "password changed successfully"
}
```

**Errors:**

| Status | Condition                        | Error Message                              |
|--------|----------------------------------|--------------------------------------------|
| 400    | Missing required fields          | `current_password and new_password are required` |
| 400    | New password validation failure  | Same password validation errors as signup  |
| 401    | Missing/invalid/expired token    | `missing authorization header` / `invalid or expired token` |
| 401    | Wrong current password           | `invalid email or password`                |
| 404    | User not found                   | `user not found`                           |
| 500    | Internal error                   | `internal server error`                    |

---

# Role Management

## Assign Role

### `POST /v1/auth/users/{user_id}/roles`

Assigns a role to a user.

**Authentication:** Required (Bearer token in `Authorization` header)

**Path Parameters:**

| Parameter | Type   | Description              |
|-----------|--------|--------------------------|
| `user_id` | string | UUID of the target user  |

**Headers:**

| Header          | Required | Description              |
|-----------------|----------|--------------------------|
| `Authorization` | Yes      | `Bearer <access_token>` |

**Request Body:**

| Field     | Type   | Required | Description           |
|-----------|--------|----------|-----------------------|
| `role_id` | string | Yes      | UUID of the role to assign |

**Business Logic:**

1. Inserts a record into the `user_roles` table linking the user and role.

**Response:**

- `200 OK`

```json
{
  "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "role_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901"
}
```

**Errors:**

| Status | Condition                    | Error Message                   |
|--------|------------------------------|---------------------------------|
| 400    | Invalid user_id or role_id   | `invalid user_id` / `invalid role_id` |
| 401    | Missing/invalid/expired token| `missing authorization header` / `invalid or expired token` |
| 500    | Internal error               | `internal server error`         |

---

## Remove Role

### `DELETE /v1/auth/users/{user_id}/roles/{role_id}`

Removes a role from a user.

**Authentication:** Required (Bearer token in `Authorization` header)

**Path Parameters:**

| Parameter | Type   | Description               |
|-----------|--------|---------------------------|
| `user_id` | string | UUID of the target user   |
| `role_id` | string | UUID of the role to remove |

**Headers:**

| Header          | Required | Description              |
|-----------------|----------|--------------------------|
| `Authorization` | Yes      | `Bearer <access_token>` |

**Business Logic:**

1. Deletes the record from the `user_roles` table matching the user and role.

**Response:**

- `200 OK`

```json
{
  "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "role_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901"
}
```

**Errors:**

| Status | Condition                    | Error Message                   |
|--------|------------------------------|---------------------------------|
| 400    | Invalid user_id or role_id   | `invalid user_id` / `invalid role_id` |
| 401    | Missing/invalid/expired token| `missing authorization header` / `invalid or expired token` |
| 500    | Internal error               | `internal server error`         |

---

## Get User Roles

### `GET /v1/auth/users/{user_id}/roles`

Returns all roles assigned to a user.

**Authentication:** Required (Bearer token in `Authorization` header)

**Path Parameters:**

| Parameter | Type   | Description              |
|-----------|--------|--------------------------|
| `user_id` | string | UUID of the target user  |

**Headers:**

| Header          | Required | Description              |
|-----------------|----------|--------------------------|
| `Authorization` | Yes      | `Bearer <access_token>` |

**Business Logic:**

1. Joins the `roles` and `user_roles` tables to fetch all roles for the given user.

**Response:**

- `200 OK`

```json
{
  "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "roles": [
    {
      "role_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "role_name": "admin"
    },
    {
      "role_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "role_name": "moderator"
    }
  ]
}
```

**Errors:**

| Status | Condition                    | Error Message                   |
|--------|------------------------------|---------------------------------|
| 400    | Invalid user_id              | `invalid user_id`               |
| 401    | Missing/invalid/expired token| `missing authorization header` / `invalid or expired token` |
| 500    | Internal error               | `internal server error`         |

---

# Appendix

## Authentication

Protected endpoints require a valid JWT in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

The auth middleware:

1. Extracts the Bearer token from the `Authorization` header.
2. Verifies the JWT signature using the RSA public key (RS256).
3. Validates expiration.
4. Extracts `sub` (user ID) and `session_id` claims and injects them into the request context.

---

## Error Response Format

All errors follow a consistent format:

```json
{
  "error": "error message here"
}
```

---

## Assumptions

- Apps must be pre-created in the database before users can sign up. There is no app creation API yet.
- JWT access tokens are signed with RS256 using an RSA private key loaded from a PEM file (`/keys/private.pem`). Verification uses the corresponding public key (`/keys/public.pem`).
- Access tokens expire after 15 minutes; sessions after 24 hours; refresh tokens after 30 days.
- The refresh token returned to the client is the raw hex-encoded value. Only its SHA-256 hash is stored in the database.
- User-Agent and client IP are captured during login and stored with the session.
- Login returns a generic "invalid email or password" for all authentication failures (wrong email, wrong password, inactive user) to avoid leaking user existence.
