-- =============================================================================
-- ShieldIaC — Initial Migration (001)
-- Applies the complete schema from schema.sql
-- =============================================================================

-- This migration applies the full initial schema.
-- In a production system, each subsequent migration would be incremental.

\i ../schema.sql

-- Migration metadata
CREATE TABLE IF NOT EXISTS _migrations (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL UNIQUE,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO _migrations (name) VALUES ('001_initial');
