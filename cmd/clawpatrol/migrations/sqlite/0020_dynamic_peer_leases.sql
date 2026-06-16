-- Transient dynamic peer leases.
--
-- Stateless workloads self-register through configured authorizers. The
-- gateway persists leases so heartbeats survive gateway restarts and expired
-- peers can be revoked from transport state, devices, and peer_api_tokens.
CREATE TABLE IF NOT EXISTS dynamic_peer_leases (
  peer_ip              TEXT PRIMARY KEY,
  transport            TEXT NOT NULL,
  authorizer_type      TEXT NOT NULL,
  authorizer_name      TEXT NOT NULL,
  subject_key          TEXT NOT NULL,
  replacement_key      TEXT NOT NULL,
  display_name         TEXT NOT NULL,
  owner                TEXT NOT NULL,
  profile              TEXT NOT NULL,
  wireguard_public_key TEXT,
  metadata_json        TEXT NOT NULL DEFAULT '{}',
  expires_ns           INTEGER NOT NULL,
  last_heartbeat_ns    INTEGER NOT NULL,
  created_ns           INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS dynamic_peer_leases_subject
  ON dynamic_peer_leases(subject_key);

CREATE INDEX IF NOT EXISTS dynamic_peer_leases_replacement
  ON dynamic_peer_leases(replacement_key);

CREATE INDEX IF NOT EXISTS dynamic_peer_leases_pubkey
  ON dynamic_peer_leases(wireguard_public_key);

CREATE INDEX IF NOT EXISTS dynamic_peer_leases_expires
  ON dynamic_peer_leases(expires_ns);
