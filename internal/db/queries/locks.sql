-- name: TryAdvisoryXactLock :one
-- Single-flight for background jobs across instances. Released on commit.
SELECT
  pg_try_advisory_xact_lock(hashtext(@key::TEXT));
