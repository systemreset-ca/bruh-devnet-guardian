-- ============================================================================
-- PROPOSED, NOT APPLIED. Isolated devnet wallet envelope storage.
--
-- Reviewed and applied only on explicit approval. This file is the exact SQL
-- that would be submitted, byte for byte.
--
-- Properties:
--   - immutable wallet UUID primary key; immutable scope
--     (group_id, membership_id, telegram_chat_id, telegram_user_id, network);
--   - exactly one wallet per scope AND exactly one wallet per Telegram identity
--     (telegram_chat_id, telegram_user_id, network), so a different
--     group/membership UUID mapping cannot mint a second wallet; an inconsistent
--     mapping raises instead of provisioning;
--   - network is strictly 'devnet'; accounts are frozen (frozen must be true);
--   - the envelope must match the exact reviewed CustodyEnvelope structure and
--     must agree with the row's wallet id, group, membership, network, address
--     and key version; malformed, extra, missing or null fields are rejected;
--   - the envelope is immutable in this slice: no replacement, no rotation path;
--   - every wallet creation writes an immutable append-only audit event in the
--     SAME transaction; the audit table never stores envelope material;
--   - no table privileges for PUBLIC, anon, authenticated or service_role;
--   - row level security enabled AND forced on both tables, with deny-all
--     policies;
--   - the only access paths are SECURITY DEFINER routines executable by the
--     server role alone: atomic provisioning insert, scoped metadata read,
--     Telegram-identity mapping read, and fully scoped signer-only envelope read
--     (there is no wallet-id-only envelope read and no fallback).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Structural envelope validation. Immutable, so it can back a CHECK constraint
-- that applies to every insert and every update.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.devnet_envelope_b64_ok(p_value jsonb, p_bytes integer)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_text text;
BEGIN
  IF p_value IS NULL OR pg_catalog.jsonb_typeof(p_value) <> 'string' THEN
    RETURN false;
  END IF;
  v_text := p_value #>> '{}';
  IF v_text !~ '^[A-Za-z0-9+/]+={0,2}$' THEN
    RETURN false;
  END IF;
  -- Fixed decoded length and canonical encoding (round-trips byte for byte).
  RETURN pg_catalog.octet_length(pg_catalog.decode(v_text, 'base64')) = p_bytes
     AND pg_catalog.encode(pg_catalog.decode(v_text, 'base64'), 'base64') = v_text;
END;
$$;

CREATE OR REPLACE FUNCTION public.devnet_wallets_envelope_ok(
  p_envelope             jsonb,
  p_wallet_id            uuid,
  p_group_id             uuid,
  p_membership_id        uuid,
  p_address              text,
  p_wrapping_key_version text
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_expected text[] := ARRAY[
    'address', 'encryptedSeed', 'groupId', 'membershipId', 'network', 'seedIv',
    'version', 'walletId', 'wrappedDataKey', 'wrappingIv', 'wrappingKeyVersion'
  ];
  v_actual   text[];
BEGIN
  IF p_envelope IS NULL OR pg_catalog.jsonb_typeof(p_envelope) <> 'object' THEN
    RETURN false;
  END IF;

  -- Exact key set: no extra keys, no missing keys.
  SELECT pg_catalog.array_agg(k ORDER BY k)
    INTO v_actual
    FROM pg_catalog.jsonb_object_keys(p_envelope) AS k;
  IF v_actual IS DISTINCT FROM (
    SELECT pg_catalog.array_agg(k ORDER BY k) FROM pg_catalog.unnest(v_expected) AS k
  ) THEN
    RETURN false;
  END IF;

  -- Scalar field types and values.
  IF pg_catalog.jsonb_typeof(p_envelope -> 'version') <> 'number'
     OR (p_envelope -> 'version') <> pg_catalog.to_jsonb(1) THEN
    RETURN false;
  END IF;
  IF pg_catalog.jsonb_typeof(p_envelope -> 'network') <> 'string'
     OR (p_envelope ->> 'network') <> 'devnet' THEN
    RETURN false;
  END IF;
  IF pg_catalog.jsonb_typeof(p_envelope -> 'walletId') <> 'string'
     OR pg_catalog.jsonb_typeof(p_envelope -> 'groupId') <> 'string'
     OR pg_catalog.jsonb_typeof(p_envelope -> 'membershipId') <> 'string'
     OR pg_catalog.jsonb_typeof(p_envelope -> 'address') <> 'string'
     OR pg_catalog.jsonb_typeof(p_envelope -> 'wrappingKeyVersion') <> 'string' THEN
    RETURN false;
  END IF;

  -- Envelope bindings must equal the row's identity, field by field.
  IF pg_catalog.lower(p_envelope ->> 'walletId') <> pg_catalog.lower(p_wallet_id::text)
     OR pg_catalog.lower(p_envelope ->> 'groupId') <> pg_catalog.lower(p_group_id::text)
     OR pg_catalog.lower(p_envelope ->> 'membershipId') <> pg_catalog.lower(p_membership_id::text)
     OR (p_envelope ->> 'address') <> p_address
     OR (p_envelope ->> 'wrappingKeyVersion') <> p_wrapping_key_version THEN
    RETURN false;
  END IF;

  -- Canonical base64 with exact decoded lengths: 12-byte IVs, 32-byte payload
  -- plus 16-byte GCM tag.
  RETURN public.devnet_envelope_b64_ok(p_envelope -> 'seedIv', 12)
     AND public.devnet_envelope_b64_ok(p_envelope -> 'wrappingIv', 12)
     AND public.devnet_envelope_b64_ok(p_envelope -> 'encryptedSeed', 48)
     AND public.devnet_envelope_b64_ok(p_envelope -> 'wrappedDataKey', 48);
END;
$$;

CREATE TABLE public.devnet_wallets (
  wallet_id            uuid        NOT NULL PRIMARY KEY,
  group_id             uuid        NOT NULL,
  membership_id        uuid        NOT NULL,
  telegram_chat_id     text        NOT NULL,
  telegram_user_id     text        NOT NULL,
  network              text        NOT NULL DEFAULT 'devnet',
  wrapping_key_version text        NOT NULL,
  address              text        NOT NULL,
  envelope             jsonb       NOT NULL,
  frozen               boolean     NOT NULL DEFAULT true,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT devnet_wallets_network_devnet_only CHECK (network = 'devnet'),
  CONSTRAINT devnet_wallets_frozen_only CHECK (frozen),
  CONSTRAINT devnet_wallets_chat_id_format CHECK (telegram_chat_id ~ '^-?[0-9]{1,20}$'),
  CONSTRAINT devnet_wallets_user_id_format CHECK (telegram_user_id ~ '^[0-9]{1,20}$'),
  CONSTRAINT devnet_wallets_key_version_format CHECK (wrapping_key_version ~ '^[A-Za-z0-9._-]{1,64}$'),
  CONSTRAINT devnet_wallets_address_format CHECK (address ~ '^[1-9A-HJ-NP-Za-km-z]{32,44}$'),
  CONSTRAINT devnet_wallets_address_unique UNIQUE (address),
  CONSTRAINT devnet_wallets_scope_unique
    UNIQUE (group_id, membership_id, telegram_chat_id, telegram_user_id, network),
  -- One wallet per Telegram identity, whatever UUID mapping is claimed.
  CONSTRAINT devnet_wallets_telegram_identity_unique
    UNIQUE (telegram_chat_id, telegram_user_id, network),
  CONSTRAINT devnet_wallets_envelope_valid CHECK (
    public.devnet_wallets_envelope_ok(
      envelope, wallet_id, group_id, membership_id, address, wrapping_key_version
    )
  )
);

-- Immutable append-only creation audit. Never stores envelope material.
CREATE TABLE public.devnet_wallet_events (
  event_id             uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  wallet_id            uuid        NOT NULL REFERENCES public.devnet_wallets (wallet_id),
  event_type           text        NOT NULL,
  group_id             uuid        NOT NULL,
  membership_id        uuid        NOT NULL,
  telegram_chat_id     text        NOT NULL,
  telegram_user_id     text        NOT NULL,
  network              text        NOT NULL,
  address              text        NOT NULL,
  wrapping_key_version text        NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT devnet_wallet_events_type CHECK (event_type = 'wallet_created'),
  CONSTRAINT devnet_wallet_events_network CHECK (network = 'devnet'),
  CONSTRAINT devnet_wallet_events_wallet_once UNIQUE (wallet_id, event_type)
);

CREATE INDEX devnet_wallet_events_wallet_idx ON public.devnet_wallet_events (wallet_id);

-- No Data API role may touch either table; the routines below are the only path.
REVOKE ALL ON TABLE public.devnet_wallets FROM PUBLIC;
REVOKE ALL ON TABLE public.devnet_wallets FROM anon;
REVOKE ALL ON TABLE public.devnet_wallets FROM authenticated;
REVOKE ALL ON TABLE public.devnet_wallets FROM service_role;
REVOKE ALL ON TABLE public.devnet_wallet_events FROM PUBLIC;
REVOKE ALL ON TABLE public.devnet_wallet_events FROM anon;
REVOKE ALL ON TABLE public.devnet_wallet_events FROM authenticated;
REVOKE ALL ON TABLE public.devnet_wallet_events FROM service_role;

ALTER TABLE public.devnet_wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.devnet_wallets FORCE ROW LEVEL SECURITY;
ALTER TABLE public.devnet_wallet_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.devnet_wallet_events FORCE ROW LEVEL SECURITY;

CREATE POLICY "no direct select" ON public.devnet_wallets FOR SELECT USING (false);
CREATE POLICY "no direct insert" ON public.devnet_wallets FOR INSERT WITH CHECK (false);
CREATE POLICY "no direct update" ON public.devnet_wallets FOR UPDATE USING (false) WITH CHECK (false);
CREATE POLICY "no direct delete" ON public.devnet_wallets FOR DELETE USING (false);

CREATE POLICY "no direct select" ON public.devnet_wallet_events FOR SELECT USING (false);
CREATE POLICY "no direct insert" ON public.devnet_wallet_events FOR INSERT WITH CHECK (false);
CREATE POLICY "no direct update" ON public.devnet_wallet_events FOR UPDATE USING (false) WITH CHECK (false);
CREATE POLICY "no direct delete" ON public.devnet_wallet_events FOR DELETE USING (false);

-- Immutable scope/identity/envelope enforcement, independent of privileges.
CREATE OR REPLACE FUNCTION public.devnet_wallets_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.wallet_id            IS DISTINCT FROM OLD.wallet_id
  OR NEW.group_id             IS DISTINCT FROM OLD.group_id
  OR NEW.membership_id        IS DISTINCT FROM OLD.membership_id
  OR NEW.telegram_chat_id     IS DISTINCT FROM OLD.telegram_chat_id
  OR NEW.telegram_user_id     IS DISTINCT FROM OLD.telegram_user_id
  OR NEW.network              IS DISTINCT FROM OLD.network
  OR NEW.wrapping_key_version IS DISTINCT FROM OLD.wrapping_key_version
  OR NEW.address              IS DISTINCT FROM OLD.address
  OR NEW.frozen               IS DISTINCT FROM OLD.frozen
  OR NEW.envelope             IS DISTINCT FROM OLD.envelope
  OR NEW.created_at           IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'immutable wallet record';
  END IF;
  NEW.updated_at := pg_catalog.now();
  RETURN NEW;
END;
$$;

CREATE TRIGGER devnet_wallets_immutable
BEFORE UPDATE ON public.devnet_wallets
FOR EACH ROW EXECUTE FUNCTION public.devnet_wallets_immutable();

-- Audit rows are append-only: no update and no delete, ever.
CREATE OR REPLACE FUNCTION public.devnet_wallet_events_append_only()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'append-only audit';
END;
$$;

CREATE TRIGGER devnet_wallet_events_append_only
BEFORE UPDATE OR DELETE ON public.devnet_wallet_events
FOR EACH ROW EXECUTE FUNCTION public.devnet_wallet_events_append_only();

-- ---------------------------------------------------------------------------
-- Atomic provisioning insert plus its audit event, in one transaction. First
-- writer wins; a concurrent loser receives the persisted row and its own
-- candidate envelope is never stored. An inconsistent Telegram-identity mapping
-- raises rather than provisioning a second wallet.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.provision_devnet_wallet(
  p_wallet_id            uuid,
  p_group_id             uuid,
  p_membership_id        uuid,
  p_telegram_chat_id     text,
  p_telegram_user_id     text,
  p_wrapping_key_version text,
  p_address              text,
  p_envelope             jsonb
)
RETURNS TABLE (wallet_id uuid, address text, wrapping_key_version text, created boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_created boolean := false;
  v_row     public.devnet_wallets;
BEGIN
  IF p_wallet_id IS NULL OR p_group_id IS NULL OR p_membership_id IS NULL THEN
    RAISE EXCEPTION 'invalid wallet input';
  END IF;
  IF p_telegram_chat_id IS NULL OR p_telegram_chat_id !~ '^-?[0-9]{1,20}$' THEN
    RAISE EXCEPTION 'invalid chat id';
  END IF;
  IF p_telegram_user_id IS NULL OR p_telegram_user_id !~ '^[0-9]{1,20}$' THEN
    RAISE EXCEPTION 'invalid user id';
  END IF;
  IF p_wrapping_key_version IS NULL OR p_wrapping_key_version !~ '^[A-Za-z0-9._-]{1,64}$' THEN
    RAISE EXCEPTION 'invalid key version';
  END IF;
  IF p_address IS NULL OR p_address !~ '^[1-9A-HJ-NP-Za-km-z]{32,44}$' THEN
    RAISE EXCEPTION 'invalid address';
  END IF;
  IF NOT public.devnet_wallets_envelope_ok(
       p_envelope, p_wallet_id, p_group_id, p_membership_id, p_address, p_wrapping_key_version
     ) THEN
    RAISE EXCEPTION 'invalid envelope';
  END IF;

  -- One wallet per Telegram identity: a changed UUID mapping is fail-closed.
  SELECT w.* INTO v_row
  FROM public.devnet_wallets w
  WHERE w.telegram_chat_id = p_telegram_chat_id
    AND w.telegram_user_id = p_telegram_user_id
    AND w.network = 'devnet';

  IF v_row.wallet_id IS NOT NULL THEN
    IF v_row.group_id IS DISTINCT FROM p_group_id
       OR v_row.membership_id IS DISTINCT FROM p_membership_id THEN
      RAISE EXCEPTION 'inconsistent wallet mapping';
    END IF;
    RETURN QUERY SELECT v_row.wallet_id, v_row.address, v_row.wrapping_key_version, false;
    RETURN;
  END IF;

  BEGIN
    INSERT INTO public.devnet_wallets AS w (
      wallet_id, group_id, membership_id, telegram_chat_id, telegram_user_id,
      network, wrapping_key_version, address, envelope, frozen
    ) VALUES (
      p_wallet_id, p_group_id, p_membership_id, p_telegram_chat_id, p_telegram_user_id,
      'devnet', p_wrapping_key_version, p_address, p_envelope, true
    )
    ON CONFLICT ON CONSTRAINT devnet_wallets_scope_unique DO NOTHING
    RETURNING w.* INTO v_row;
  EXCEPTION WHEN unique_violation THEN
    -- Concurrent winner claimed this Telegram identity or address.
    v_row := NULL;
  END;

  IF v_row.wallet_id IS NOT NULL THEN
    v_created := true;
    -- Same transaction as the wallet row: an unaudited wallet cannot exist.
    INSERT INTO public.devnet_wallet_events (
      wallet_id, event_type, group_id, membership_id, telegram_chat_id,
      telegram_user_id, network, address, wrapping_key_version
    ) VALUES (
      v_row.wallet_id, 'wallet_created', v_row.group_id, v_row.membership_id,
      v_row.telegram_chat_id, v_row.telegram_user_id, v_row.network, v_row.address,
      v_row.wrapping_key_version
    );
  ELSE
    SELECT w.* INTO v_row
    FROM public.devnet_wallets w
    WHERE w.telegram_chat_id = p_telegram_chat_id
      AND w.telegram_user_id = p_telegram_user_id
      AND w.network = 'devnet';
    IF v_row.wallet_id IS NULL THEN
      RAISE EXCEPTION 'provisioning conflict';
    END IF;
    IF v_row.group_id IS DISTINCT FROM p_group_id
       OR v_row.membership_id IS DISTINCT FROM p_membership_id THEN
      RAISE EXCEPTION 'inconsistent wallet mapping';
    END IF;
  END IF;

  RETURN QUERY SELECT v_row.wallet_id, v_row.address, v_row.wrapping_key_version, v_created;
END;
$$;

-- Scoped metadata only: no envelope column is ever selected here.
CREATE OR REPLACE FUNCTION public.read_devnet_wallet_scoped(
  p_group_id         uuid,
  p_membership_id    uuid,
  p_telegram_chat_id text,
  p_telegram_user_id text
)
RETURNS TABLE (wallet_id uuid, address text, wrapping_key_version text, frozen boolean)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT w.wallet_id, w.address, w.wrapping_key_version, w.frozen
  FROM public.devnet_wallets w
  WHERE w.group_id = p_group_id
    AND w.membership_id = p_membership_id
    AND w.telegram_chat_id = p_telegram_chat_id
    AND w.telegram_user_id = p_telegram_user_id
    AND w.network = 'devnet';
$$;

-- Telegram-identity mapping, so the service can fail closed on a changed
-- group/membership mapping. Metadata only, no envelope and no address.
CREATE OR REPLACE FUNCTION public.read_devnet_wallet_by_telegram(
  p_telegram_chat_id text,
  p_telegram_user_id text
)
RETURNS TABLE (
  wallet_id uuid, group_id uuid, membership_id uuid,
  telegram_chat_id text, telegram_user_id text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT w.wallet_id, w.group_id, w.membership_id, w.telegram_chat_id, w.telegram_user_id
  FROM public.devnet_wallets w
  WHERE w.telegram_chat_id = p_telegram_chat_id
    AND w.telegram_user_id = p_telegram_user_id
    AND w.network = 'devnet';
$$;

-- Signer-only envelope read. FULLY SCOPED: wallet id AND group AND membership
-- AND chat AND user must all match the same row. There is no wallet-id-only
-- read and no fallback: a mismatch returns no row.
CREATE OR REPLACE FUNCTION public.read_devnet_wallet_envelope(
  p_wallet_id        uuid,
  p_group_id         uuid,
  p_membership_id    uuid,
  p_telegram_chat_id text,
  p_telegram_user_id text
)
RETURNS TABLE (envelope jsonb)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT w.envelope
  FROM public.devnet_wallets w
  WHERE w.wallet_id = p_wallet_id
    AND w.group_id = p_group_id
    AND w.membership_id = p_membership_id
    AND w.telegram_chat_id = p_telegram_chat_id
    AND w.telegram_user_id = p_telegram_user_id
    AND w.network = 'devnet';
$$;

REVOKE ALL ON FUNCTION public.provision_devnet_wallet(uuid, uuid, uuid, text, text, text, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.provision_devnet_wallet(uuid, uuid, uuid, text, text, text, text, jsonb) FROM anon;
REVOKE ALL ON FUNCTION public.provision_devnet_wallet(uuid, uuid, uuid, text, text, text, text, jsonb) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.provision_devnet_wallet(uuid, uuid, uuid, text, text, text, text, jsonb) TO service_role;

REVOKE ALL ON FUNCTION public.read_devnet_wallet_scoped(uuid, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.read_devnet_wallet_scoped(uuid, uuid, text, text) FROM anon;
REVOKE ALL ON FUNCTION public.read_devnet_wallet_scoped(uuid, uuid, text, text) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.read_devnet_wallet_scoped(uuid, uuid, text, text) TO service_role;

REVOKE ALL ON FUNCTION public.read_devnet_wallet_by_telegram(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.read_devnet_wallet_by_telegram(text, text) FROM anon;
REVOKE ALL ON FUNCTION public.read_devnet_wallet_by_telegram(text, text) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.read_devnet_wallet_by_telegram(text, text) TO service_role;

REVOKE ALL ON FUNCTION public.read_devnet_wallet_envelope(uuid, uuid, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.read_devnet_wallet_envelope(uuid, uuid, uuid, text, text) FROM anon;
REVOKE ALL ON FUNCTION public.read_devnet_wallet_envelope(uuid, uuid, uuid, text, text) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.read_devnet_wallet_envelope(uuid, uuid, uuid, text, text) TO service_role;

REVOKE ALL ON FUNCTION public.devnet_wallets_envelope_ok(jsonb, uuid, uuid, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.devnet_wallets_envelope_ok(jsonb, uuid, uuid, uuid, text, text) FROM anon;
REVOKE ALL ON FUNCTION public.devnet_wallets_envelope_ok(jsonb, uuid, uuid, uuid, text, text) FROM authenticated;
REVOKE ALL ON FUNCTION public.devnet_wallets_envelope_ok(jsonb, uuid, uuid, uuid, text, text) FROM service_role;

REVOKE ALL ON FUNCTION public.devnet_envelope_b64_ok(jsonb, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.devnet_envelope_b64_ok(jsonb, integer) FROM anon;
REVOKE ALL ON FUNCTION public.devnet_envelope_b64_ok(jsonb, integer) FROM authenticated;
REVOKE ALL ON FUNCTION public.devnet_envelope_b64_ok(jsonb, integer) FROM service_role;

REVOKE ALL ON FUNCTION public.devnet_wallets_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.devnet_wallets_immutable() FROM anon;
REVOKE ALL ON FUNCTION public.devnet_wallets_immutable() FROM authenticated;
REVOKE ALL ON FUNCTION public.devnet_wallets_immutable() FROM service_role;

REVOKE ALL ON FUNCTION public.devnet_wallet_events_append_only() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.devnet_wallet_events_append_only() FROM anon;
REVOKE ALL ON FUNCTION public.devnet_wallet_events_append_only() FROM authenticated;
REVOKE ALL ON FUNCTION public.devnet_wallet_events_append_only() FROM service_role;
