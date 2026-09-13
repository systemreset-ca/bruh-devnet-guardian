-- PROPOSED — NOT APPLIED.
-- Awaiting the owner's source/test review before any Cloud application.
--
-- Aligns public.consume_signer_nonce with the verifier and hardens ACLs:
--   1. Fixed retention: any ttl_seconds other than 300 is rejected. A shorter
--      TTL (e.g. 1s) would let a nonce be reclaimed while the 60-second
--      timestamp window is still valid, permitting replay.
--   2. key_id  must match ^[A-Za-z0-9._-]{1,64}$      (verifier's KEY_ID_PATTERN)
--   3. nonce   must match ^[0-9a-f]{32,64}$           (canonical lowercase hex)
--   4. SECURITY DEFINER with SET search_path = pg_catalog and every table
--      reference schema-qualified, so pg_temp cannot shadow anything.
--   5. Table privileges revoked from PUBLIC as well as every API role.

-- Fixed retention, matching the verifier's NONCE_TTL_MS (300_000 ms).
CREATE OR REPLACE FUNCTION public.consume_signer_nonce(
  p_key_id text,
  p_nonce text,
  p_ttl_seconds integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_now       timestamptz := pg_catalog.now();
  v_expires   timestamptz;
  v_first_use boolean;
BEGIN
  IF p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9._-]{1,64}$' THEN
    RAISE EXCEPTION 'invalid key id';
  END IF;

  -- Canonical lowercase hex only; the verifier lowercases before calling.
  IF p_nonce IS NULL OR p_nonce !~ '^[0-9a-f]{32,64}$' THEN
    RAISE EXCEPTION 'invalid nonce';
  END IF;

  -- Fixed retention. A shorter window would allow replay inside the
  -- verifier's timestamp skew window.
  IF p_ttl_seconds IS NULL OR p_ttl_seconds <> 300 THEN
    RAISE EXCEPTION 'invalid ttl';
  END IF;

  v_expires := v_now + pg_catalog.make_interval(secs => 300);

  -- Bounded opportunistic cleanup of expired rows.
  DELETE FROM public.signer_nonces sn
  WHERE sn.ctid IN (
    SELECT e.ctid FROM public.signer_nonces e
    WHERE e.expires_at < v_now
    LIMIT 200
  );

  -- Atomic first-use claim; a live row is never reclaimable.
  INSERT INTO public.signer_nonces AS t (key_id, nonce, consumed_at, expires_at)
  VALUES (p_key_id, p_nonce, v_now, v_expires)
  ON CONFLICT (key_id, nonce) DO UPDATE
    SET consumed_at = v_now,
        expires_at  = v_expires
    WHERE t.expires_at < v_now
  RETURNING true INTO v_first_use;

  RETURN pg_catalog.coalesce(v_first_use, false);
END;
$$;

-- Table privileges: deny PUBLIC as well as every API role.
REVOKE ALL ON TABLE public.signer_nonces FROM PUBLIC;
REVOKE ALL ON TABLE public.signer_nonces FROM anon;
REVOKE ALL ON TABLE public.signer_nonces FROM authenticated;
REVOKE ALL ON TABLE public.signer_nonces FROM service_role;

-- Routine privileges: only the server role may execute it.
REVOKE ALL ON FUNCTION public.consume_signer_nonce(text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.consume_signer_nonce(text, text, integer) FROM anon;
REVOKE ALL ON FUNCTION public.consume_signer_nonce(text, text, integer) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.consume_signer_nonce(text, text, integer) TO service_role;
