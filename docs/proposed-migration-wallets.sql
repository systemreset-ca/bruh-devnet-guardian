-- ============================================================================
-- PROPOSED, NOT APPLIED. Isolated devnet wallet envelope storage.
--
-- Reviewed and applied only on explicit approval. This file is the exact SQL
-- that would be submitted, byte for byte.
--
-- Properties:
--   - immutable wallet UUID primary key; immutable scope
--     (group_id, membership_id, telegram_chat_id, telegram_user_id, network);
--   - exactly one wallet per scope (unique constraint) and one address per row;
--   - network is strictly 'devnet'; accounts are frozen (frozen must be true);
--   - the authenticated encrypted envelope is stored as opaque jsonb and is
--     never exposed to an API role or a client;
--   - no table privileges for PUBLIC, anon, authenticated or service_role;
--   - row level security enabled AND forced, with deny-all policies;
--   - the only access paths are three SECURITY DEFINER routines executable by
--     the server role alone: atomic provisioning insert, public metadata read,
--     and signer-only envelope read;
--   - immutable columns are enforced by a BEFORE UPDATE trigger as well as by
--     the absence of any update privilege.
-- ============================================================================

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
    UNIQUE (group_id, membership_id, telegram_chat_id, telegram_user_id, network)
);

-- No Data API role may touch the table; the routines below are the only path.
REVOKE ALL ON TABLE public.devnet_wallets FROM PUBLIC;
REVOKE ALL ON TABLE public.devnet_wallets FROM anon;
REVOKE ALL ON TABLE public.devnet_wallets FROM authenticated;
REVOKE ALL ON TABLE public.devnet_wallets FROM service_role;

ALTER TABLE public.devnet_wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.devnet_wallets FORCE ROW LEVEL SECURITY;

CREATE POLICY "no direct select" ON public.devnet_wallets FOR SELECT USING (false);
CREATE POLICY "no direct insert" ON public.devnet_wallets FOR INSERT WITH CHECK (false);
CREATE POLICY "no direct update" ON public.devnet_wallets FOR UPDATE USING (false) WITH CHECK (false);
CREATE POLICY "no direct delete" ON public.devnet_wallets FOR DELETE USING (false);

-- Immutable scope/identity enforcement, independent of privileges.
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
  OR NEW.created_at           IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'immutable wallet scope';
  END IF;
  NEW.updated_at := pg_catalog.now();
  RETURN NEW;
END;
$$;

CREATE TRIGGER devnet_wallets_immutable
BEFORE UPDATE ON public.devnet_wallets
FOR EACH ROW EXECUTE FUNCTION public.devnet_wallets_immutable();

-- ---------------------------------------------------------------------------
-- Atomic provisioning insert. First writer wins; a concurrent loser receives
-- the persisted row and its own candidate envelope is never stored.
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
  IF p_wallet_id IS NULL OR p_group_id IS NULL OR p_membership_id IS NULL
     OR p_envelope IS NULL OR pg_catalog.jsonb_typeof(p_envelope) <> 'object' THEN
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

  INSERT INTO public.devnet_wallets AS w (
    wallet_id, group_id, membership_id, telegram_chat_id, telegram_user_id,
    network, wrapping_key_version, address, envelope, frozen
  ) VALUES (
    p_wallet_id, p_group_id, p_membership_id, p_telegram_chat_id, p_telegram_user_id,
    'devnet', p_wrapping_key_version, p_address, p_envelope, true
  )
  ON CONFLICT ON CONSTRAINT devnet_wallets_scope_unique DO NOTHING
  RETURNING w.* INTO v_row;

  IF v_row.wallet_id IS NOT NULL THEN
    v_created := true;
  ELSE
    SELECT w.* INTO v_row
    FROM public.devnet_wallets w
    WHERE w.group_id = p_group_id
      AND w.membership_id = p_membership_id
      AND w.telegram_chat_id = p_telegram_chat_id
      AND w.telegram_user_id = p_telegram_user_id
      AND w.network = 'devnet';
    IF v_row.wallet_id IS NULL THEN
      RAISE EXCEPTION 'provisioning conflict';
    END IF;
  END IF;

  RETURN QUERY SELECT v_row.wallet_id, v_row.address, v_row.wrapping_key_version, v_created;
END;
$$;

-- Public metadata only: no envelope column is ever selected here.
CREATE OR REPLACE FUNCTION public.read_devnet_wallet_public(
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

-- Signer-only envelope read, by immutable wallet id.
CREATE OR REPLACE FUNCTION public.read_devnet_wallet_envelope(p_wallet_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT w.envelope FROM public.devnet_wallets w WHERE w.wallet_id = p_wallet_id;
$$;

REVOKE ALL ON FUNCTION public.provision_devnet_wallet(uuid, uuid, uuid, text, text, text, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.provision_devnet_wallet(uuid, uuid, uuid, text, text, text, text, jsonb) FROM anon;
REVOKE ALL ON FUNCTION public.provision_devnet_wallet(uuid, uuid, uuid, text, text, text, text, jsonb) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.provision_devnet_wallet(uuid, uuid, uuid, text, text, text, text, jsonb) TO service_role;

REVOKE ALL ON FUNCTION public.read_devnet_wallet_public(uuid, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.read_devnet_wallet_public(uuid, uuid, text, text) FROM anon;
REVOKE ALL ON FUNCTION public.read_devnet_wallet_public(uuid, uuid, text, text) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.read_devnet_wallet_public(uuid, uuid, text, text) TO service_role;

REVOKE ALL ON FUNCTION public.read_devnet_wallet_envelope(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.read_devnet_wallet_envelope(uuid) FROM anon;
REVOKE ALL ON FUNCTION public.read_devnet_wallet_envelope(uuid) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.read_devnet_wallet_envelope(uuid) TO service_role;

REVOKE ALL ON FUNCTION public.devnet_wallets_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.devnet_wallets_immutable() FROM anon;
REVOKE ALL ON FUNCTION public.devnet_wallets_immutable() FROM authenticated;
REVOKE ALL ON FUNCTION public.devnet_wallets_immutable() FROM service_role;
