-- name: GetAccessGraph :many
-- One row per node and edge of the graph, told apart by the by_ flags. The row with none set is the total.
WITH
  matched AS (
    SELECT
      g.subject_id,
      g.subject_kind,
      p.username,
      p.target_id,
      u.tag
    FROM
      live_grants g
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
        -- One array of ids, an OR over the teams would keep the lookup off the subject index.
        OR g.subject_id = ANY (
          ARRAY[sqlc.narg('subject_id')::UUID] || ARRAY(
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
-- The targets of one tag, the ones with a matching grant first. The filter is the one GetAccessGraph takes.
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
        live_grants g
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

-- name: ListAccessMatrixRows :many
-- Whoever holds a live grant, teams first, then people and service accounts by name. Deactivated people are left out.
-- Pages before it counts, so only the rows shown pay for their server counts.
WITH
  page AS (
    SELECT
      h.subject_id,
      h.subject_kind,
      COALESCE(NULLIF(u.name, ''), u.email, m.name, s.name, '')::TEXT AS name,
      COALESCE(u.email, '')::TEXT AS email,
      m.id AS team_id,
      (COUNT(*) OVER ())::INTEGER AS total
    FROM
      (
        SELECT DISTINCT
          g.subject_id,
          g.subject_kind
        FROM
          live_grants g
      ) h
      LEFT JOIN users u ON u.id = h.subject_id
      LEFT JOIN teams m ON m.id = h.subject_id
      LEFT JOIN service_accounts s ON s.id = h.subject_id
    WHERE
      (
        sqlc.narg('kind')::TEXT IS NULL
        OR h.subject_kind = sqlc.narg('kind')::TEXT
      )
      AND (
        sqlc.narg('query')::TEXT IS NULL
        OR COALESCE(NULLIF(u.name, ''), u.email, m.name, s.name, '') ILIKE '%' || sqlc.narg('query') || '%'
        OR COALESCE(u.email, '') ILIKE '%' || sqlc.narg('query') || '%'
      )
      AND COALESCE(u.active, TRUE)
    ORDER BY
      CASE h.subject_kind
        WHEN 'team' THEN 0
        WHEN 'user' THEN 1
        ELSE 2
      END,
      lower(COALESCE(NULLIF(u.name, ''), u.email, m.name, s.name, '')),
      h.subject_id
    LIMIT
      sqlc.arg('limit')
    OFFSET
      sqlc.arg('offset')
  )
SELECT
  p.subject_id::UUID AS subject_id,
  p.subject_kind::TEXT AS subject_kind,
  p.name,
  p.email,
  (
    SELECT
      COUNT(*)
    FROM
      team_members tm
    WHERE
      tm.team_id = p.team_id
  )::INTEGER AS member_count,
  (
    SELECT
      COUNT(DISTINCT a.target_id)
    FROM
      live_grants g
      JOIN target_accounts a ON a.id = g.account_id
    WHERE
      g.subject_id = p.subject_id
  )::INTEGER AS targets,
  p.total
FROM
  page p
ORDER BY
  CASE p.subject_kind
    WHEN 'team' THEN 0
    WHEN 'user' THEN 1
    ELSE 2
  END,
  lower(p.name),
  p.subject_id;

-- name: ListAccessMatrixCells :many
-- Last use is per subject and server, so a server with many tags is looked up once, and a team's is its members'.
WITH
  cells AS (
    SELECT
      g.subject_id,
      g.team_id,
      u.tag,
      p.target_id,
      p.username,
      g.expires_at
    FROM
      live_grants g
      JOIN target_accounts p ON p.id = g.account_id
      JOIN targets t ON t.id = p.target_id
      CROSS JOIN LATERAL unnest(
        CASE
          WHEN t.tags = '{}' THEN ARRAY['']
          ELSE t.tags
        END
      ) AS u (tag)
    WHERE
      g.subject_id = ANY (@subject_ids::UUID[])
      AND u.tag = ANY (@tags::TEXT[])
  ),
  used AS (
    SELECT
      c.subject_id,
      c.target_id,
      max(au.last_cert_at) AS last_used_at
    FROM
      (
        SELECT DISTINCT
          subject_id,
          team_id,
          target_id
        FROM
          cells
      ) c
      JOIN access_usage au ON au.target_id = c.target_id
    WHERE
      au.subject_id = c.subject_id
      OR EXISTS (
        SELECT
          1
        FROM
          team_members tm
        WHERE
          tm.team_id = c.team_id
          AND tm.user_id = au.subject_id
      )
    GROUP BY
      c.subject_id,
      c.target_id
  )
SELECT
  c.subject_id::UUID AS subject_id,
  c.tag::TEXT AS tag,
  COUNT(DISTINCT c.target_id)::INTEGER AS targets,
  array_agg(DISTINCT c.username ORDER BY c.username)::TEXT[] AS usernames,
  bool_or(c.expires_at IS NULL)::BOOLEAN AS for_good,
  COALESCE(max(c.expires_at), 'epoch')::TIMESTAMPTZ AS expires_at,
  (max(us.last_used_at) IS NOT NULL)::BOOLEAN AS used,
  COALESCE(max(us.last_used_at), 'epoch')::TIMESTAMPTZ AS last_used_at
FROM
  cells c
  LEFT JOIN used us ON us.subject_id = c.subject_id
  AND us.target_id = c.target_id
GROUP BY
  c.subject_id,
  c.tag;
