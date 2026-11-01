-- name: TryAdvisoryXactLock :one
-- Single-flight for background jobs across instances. Released on commit.
SELECT
  pg_try_advisory_xact_lock(hashtext(@key::TEXT));

-- name: QuietStateChange :exec
-- This transaction only concerns one server, so no other daemon is woken. Ends with the transaction.
SELECT
  set_config('nokku.quiet', 'on', TRUE);
