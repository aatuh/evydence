-- Idempotency responses created before EVY-302 may contain a one-time
-- credential at the top level. Preserve the durable resource fields while
-- making those legacy records safe to replay.
UPDATE idempotency_records
SET response = response - ARRAY[
    'secret',
    'password',
    'token',
    'authorization',
    'access_token',
    'refresh_token',
    'id_token',
    'session_token',
    'client_secret',
    'private_key',
    'credential'
]
WHERE jsonb_typeof(response) = 'object'
  AND response ?| ARRAY[
      'secret',
      'password',
      'token',
      'authorization',
      'access_token',
      'refresh_token',
      'id_token',
      'session_token',
      'client_secret',
      'private_key',
      'credential'
  ];
