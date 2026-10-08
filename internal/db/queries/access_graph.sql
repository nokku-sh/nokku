-- name: GetAccessGraph :many
-- One row per node and edge of the graph, told apart by the by_ flags. The
-- row with none set is the total. A target with several tags counts under
-- each of them, an untagged one under ''.
WITH
  matched AS (
    SELECT
      g.subject_id,
      g.subject_kind,
      p.username,
      p.target_id,
      u.tag
    FROM
      grants g
      JOIN target_accounts p ON p.id = g.account_id
      JOIN targets t ON t.id = p.target_id
      CROSS JOIN LATERAL unnest(
        CASE
          WHEN t.tags = '{}' THEN ARRAY['']
          ELSE t.tags
        END
      ) AS u (tag)
    WHERE
      (
        sqlc.narg('subject_id')::UUID IS NULL
        OR g.subject_id = sqlc.narg('subject_id')::UUID
        OR (
          g.subject_kind = 'team'
          AND g.subject_id IN (
            SELECT
              tm.team_id
            FROM
              team_members tm
            WHERE
              tm.user_id = sqlc.narg('subject_id')::UUID
          )
        )
      )
      AND (
        sqlc.narg('target_id')::UUID IS NULL
        OR p.target_id = sqlc.narg('target_id')::UUID
      )
      AND (
        sqlc.narg('username')::TEXT IS NULL
        OR p.username = sqlc.narg('username')::TEXT
      )
      AND (
        sqlc.narg('tag')::TEXT IS NULL
        OR u.tag = sqlc.narg('tag')::TEXT
      )
  )
SELECT
  (GROUPING(m.subject_id) = 0)::BOOLEAN AS by_subject,
  (GROUPING(m.username) = 0)::BOOLEAN AS by_username,
  (GROUPING(m.tag) = 0)::BOOLEAN AS by_tag,
  COALESCE(m.subject_id::TEXT, '')::TEXT AS subject_id,
  COALESCE(m.username, '')::TEXT AS username,
  COALESCE(m.tag, '')::TEXT AS tag,
  COUNT(DISTINCT m.target_id)::INTEGER AS targets
FROM
  matched m
GROUP BY
  GROUPING SETS (
    (),
    (m.subject_id),
    (m.username),
    (m.tag),
    (m.subject_id, m.username),
    (m.username, m.tag)
  );

-- name: GetAccessGraphSubjects :many
-- Subject UUIDs are unique across kinds, so at most one branch matches an id.
SELECT
  u.id,
  'user'::TEXT AS kind,
  u.name,
  u.email,
  0::INTEGER AS member_count
FROM
  users u
WHERE
  u.id = ANY (@ids::UUID[])
UNION ALL
SELECT
  te.id,
  'team'::TEXT AS kind,
  te.name,
  ''::TEXT AS email,
  (
    SELECT
      COUNT(*)
    FROM
      team_members tm
    WHERE
      tm.team_id = te.id
  )::INTEGER AS member_count
FROM
  teams te
WHERE
  te.id = ANY (@ids::UUID[])
UNION ALL
SELECT
  sa.id,
  'service_account'::TEXT AS kind,
  sa.name,
  ''::TEXT AS email,
  0::INTEGER AS member_count
FROM
  service_accounts sa
WHERE
  sa.id = ANY (@ids::UUID[]);

-- name: CountTargetsByTag :many
SELECT
  u.tag::TEXT AS tag,
  COUNT(DISTINCT t.id)::INTEGER AS total
FROM
  targets t
  CROSS JOIN LATERAL unnest(
    CASE
      WHEN t.tags = '{}' THEN ARRAY['']
      ELSE t.tags
    END
  ) AS u (tag)
GROUP BY
  u.tag;

-- name: ListAccessGraphTargets :many
-- The targets of one tag, the ones with a matching grant first. The filter is
-- the one GetAccessGraph takes, so a tag filter only matches its own tag.
SELECT
  t.id,
  t.name,
  (
    (
      sqlc.narg('filter_tag')::TEXT IS NULL
      OR sqlc.narg('filter_tag')::TEXT = @tag::TEXT
    )
    AND (
      sqlc.narg('target_id')::UUID IS NULL
      OR t.id = sqlc.narg('target_id')::UUID
    )
    AND EXISTS (
      SELECT
        1
      FROM
        grants g
        JOIN target_accounts p ON p.id = g.account_id
      WHERE
        p.target_id = t.id
        AND (
          sqlc.narg('subject_id')::UUID IS NULL
          OR g.subject_id = sqlc.narg('subject_id')::UUID
          OR (
            g.subject_kind = 'team'
            AND g.subject_id IN (
              SELECT
                tm.team_id
              FROM
                team_members tm
              WHERE
                tm.user_id = sqlc.narg('subject_id')::UUID
            )
          )
        )
        AND (
          sqlc.narg('username')::TEXT IS NULL
          OR p.username = sqlc.narg('username')::TEXT
        )
    )
  )::BOOLEAN AS matched,
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  targets t
WHERE
  (
    @tag::TEXT = ''
    AND t.tags = '{}'
  )
  OR t.tags @> ARRAY[@tag::TEXT]
ORDER BY
  matched DESC,
  t.name ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');
