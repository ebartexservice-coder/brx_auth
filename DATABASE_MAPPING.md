# Database Mapping Documentation

This document explains how the new FastAPI auth-service maps to the legacy database structure.

## Legacy Database Tables (Preserved)

### `users` Table

**Status**: ✅ EXACT MAPPING - No column name changes

The `users` table is mapped exactly as it exists in `legacy_dump.sql`:

| Column Name | Type | Nullable | Description |
|------------|------|----------|-------------|
| `id` | BIGINT UNSIGNED | NO | Primary key, auto-increment |
| `email` | VARCHAR(255) | NO | Unique email address |
| `username` | VARCHAR(255) | NO | Unique username |
| `email_verified_at` | TIMESTAMP | YES | Email verification timestamp |
| `webhook_token` | VARCHAR(64) | YES | Webhook authentication token |
| `webhook_secret` | VARCHAR(64) | YES | Webhook secret |
| `webhook_enabled` | TINYINT(1) | YES | Webhook enabled flag |
| `webhook_last_received` | TIMESTAMP | YES | Last webhook received timestamp |
| `password` | VARCHAR(255) | NO | Hashed password (Argon2id in new system) |
| `remember_token` | VARCHAR(100) | YES | Legacy remember token |
| `created_at` | TIMESTAMP | YES | Account creation timestamp |
| `updated_at` | TIMESTAMP | YES | Last update timestamp |
| `last_login_at` | TIMESTAMP | YES | Last login timestamp |
| `account_type` | VARCHAR(255) | NO | Account type (personal/private) |
| `role` | VARCHAR(255) | NO | User role (default: 'user') |
| `verified` | TINYINT(1) | NO | Account verification status |
| `is_active` | TINYINT(1) | NO | Account active status |
| `on_vacation` | TINYINT(1) | NO | Vacation mode flag |
| `powerseller` | TINYINT(1) | NO | Powerseller flag |

**SQLAlchemy Model**: `app.infrastructure.database.models.User`

**Important Notes**:
- All column names match exactly with legacy database
- Foreign key relationships are preserved
- Indexes are maintained
- The `password` field will store Argon2id hashes (legacy bcrypt hashes can be migrated)

## New Security Tables

### `refresh_tokens` Table

**Status**: ✅ NEW TABLE - Created via Alembic migration

This table stores refresh tokens for the dual token authentication system.

| Column Name | Type | Nullable | Description |
|------------|------|----------|-------------|
| `id` | BIGINT UNSIGNED | NO | Primary key, auto-increment |
| `user_id` | BIGINT UNSIGNED | NO | Foreign key to `users.id` |
| `token` | VARCHAR(255) | NO | Unique refresh token (hashed) |
| `token_hash` | VARCHAR(255) | NO | SHA256 hash for lookup |
| `ip_address` | VARCHAR(45) | YES | IP address where token was created |
| `user_agent` | TEXT | YES | User agent string |
| `expires_at` | TIMESTAMP | NO | Token expiration timestamp |
| `revoked_at` | TIMESTAMP | YES | Token revocation timestamp |
| `revoked_reason` | VARCHAR(255) | YES | Reason for revocation |
| `created_at` | TIMESTAMP | NO | Token creation timestamp |
| `last_used_at` | TIMESTAMP | YES | Last usage timestamp |

**Foreign Key**: `user_id` → `users.id` (ON DELETE CASCADE)

**Indexes**:
- Primary key on `id`
- Unique index on `token`
- Index on `user_id`
- Index on `token_hash`
- Composite index on `(user_id, expires_at)`
- Index on `revoked_at`

**SQLAlchemy Model**: `app.infrastructure.database.models.RefreshToken`

### `login_audit_logs` Table

**Status**: ✅ NEW TABLE - Created via Alembic migration

This table tracks all login attempts (successful and failed) for security auditing.

| Column Name | Type | Nullable | Description |
|------------|------|----------|-------------|
| `id` | BIGINT UNSIGNED | NO | Primary key, auto-increment |
| `user_id` | BIGINT UNSIGNED | YES | Foreign key to `users.id` (NULL for failed attempts) |
| `email` | VARCHAR(255) | YES | Email used in login attempt |
| `ip_address` | VARCHAR(45) | NO | IP address of login attempt |
| `user_agent` | TEXT | YES | User agent string |
| `success` | BOOLEAN | NO | Whether login was successful |
| `failure_reason` | VARCHAR(255) | YES | Reason for failure (if unsuccessful) |
| `device_info` | TEXT | YES | JSON device information |
| `location_info` | TEXT | YES | JSON location information |
| `created_at` | TIMESTAMP | NO | Login attempt timestamp |

**Foreign Key**: `user_id` → `users.id` (ON DELETE SET NULL)

**Indexes**:
- Primary key on `id`
- Index on `user_id`
- Index on `email`
- Index on `ip_address`
- Index on `success`
- Index on `created_at`
- Composite indexes for common queries

**SQLAlchemy Model**: `app.infrastructure.database.models.LoginAuditLog`

### `rate_limit_events` Table

**Status**: ✅ NEW TABLE - Created via Alembic migration

This table tracks rate limiting events for brute force protection and API rate limiting.

| Column Name | Type | Nullable | Description |
|------------|------|----------|-------------|
| `id` | BIGINT UNSIGNED | NO | Primary key, auto-increment |
| `identifier` | VARCHAR(255) | NO | IP address, email, or user_id |
| `event_type` | VARCHAR(50) | NO | Event type (login_attempt, api_request, etc.) |
| `count` | BIGINT | NO | Number of events in window |
| `window_start` | TIMESTAMP | NO | Window start timestamp |
| `window_end` | TIMESTAMP | NO | Window end timestamp |
| `created_at` | TIMESTAMP | NO | Event creation timestamp |
| `updated_at` | TIMESTAMP | NO | Last update timestamp |

**Indexes**:
- Primary key on `id`
- Index on `identifier`
- Index on `event_type`
- Composite index on `(identifier, event_type)`
- Composite index on `(window_start, window_end)`

**SQLAlchemy Model**: `app.infrastructure.database.models.RateLimitEvent`

## Migration Strategy

1. **Existing Tables**: No changes to `users` table structure
2. **New Tables**: Created via Alembic migration `001_create_security_tables`
3. **Password Migration**: Legacy bcrypt passwords can be migrated to Argon2id on first successful login
4. **Data Integrity**: All foreign keys maintain referential integrity

## Running Migrations

```bash
# Create migration
alembic revision --autogenerate -m "create_security_tables"

# Apply migrations
alembic upgrade head

# Rollback if needed
alembic downgrade -1
```

## Verification

After running migrations, verify tables exist:

```sql
-- Check new tables exist
SHOW TABLES LIKE '%refresh%';
SHOW TABLES LIKE '%audit%';
SHOW TABLES LIKE '%rate%';

-- Verify foreign keys
SELECT 
    CONSTRAINT_NAME,
    TABLE_NAME,
    COLUMN_NAME,
    REFERENCED_TABLE_NAME,
    REFERENCED_COLUMN_NAME
FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
WHERE TABLE_SCHEMA = 'your_database_name'
  AND REFERENCED_TABLE_NAME IS NOT NULL;
```
