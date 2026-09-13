CREATE TABLE public.signer_nonces (
  key_id      text        NOT NULL,
  nonce       text        NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  PRIMARY KEY (key_id, nonce)
);

CREATE INDEX signer_nonces_expires_at_idx ON public.signer_nonces (expires_at);

-- Deny every Data API role direct access. Consumption happens only through the
-- SECURITY DEFINER function below.
REVOKE ALL ON TABLE public.signer_nonces FROM anon;
REVOKE ALL ON TABLE public.signer_nonces FROM authenticated;
REVOKE ALL ON TABLE public.signer_nonces FROM service_role;

ALTER TABLE public.signer_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.signer_nonces FORCE ROW LEVEL SECURITY;

-- Explicit deny policies for auditability (no policy would already deny).
CREATE POLICY "no direct select" ON public.signer_nonces FOR SELECT USING (false);
CREATE POLICY "no direct insert" ON public.signer_nonces FOR INSERT WITH CHECK (false);
CREATE POLICY "no direct update" ON public.signer_nonces FOR UPDATE USING (false) WITH CHECK (false);
CREATE POLICY "no direct delete" ON public.signer_nonces FOR DELETE USING (false);

CREATE OR REPLACE FUNCTION public.consume_signer_nonce(
  p_key_id text,
  p_nonce text,
  p_ttl_seconds integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_now       timestamptz := now();
  v_expires   timestamptz;
  v_first_use boolean;
BEGIN
  IF p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9_.:-]{8,64}$' THEN
    RAISE EXCEPTION 'invalid key id';
  END IF;

  IF p_nonce IS NULL OR p_nonce !~ '^[A-Za-z0-9_-]{16,128}$' THEN
    RAISE EXCEPTION 'invalid nonce';
  END IF;

  IF p_ttl_seconds IS NULL OR p_ttl_seconds < 1 OR p_ttl_seconds > 300 THEN
    RAISE EXCEPTION 'invalid ttl';
  END IF;

  -- Server clock only; caller-supplied timestamps are never trusted.
  v_expires := v_now + make_interval(secs => p_ttl_seconds);

  -- Bounded opportunistic cleanup of expired rows.
  DELETE FROM public.signer_nonces sn
  WHERE sn.ctid IN (
    SELECT e.ctid FROM public.signer_nonces e
    WHERE e.expires_at < v_now
    LIMIT 200
  );

  -- Atomic first-use claim: the conflicting row is only reclaimable once expired.
  INSERT INTO public.signer_nonces AS t (key_id, nonce, consumed_at, expires_at)
  VALUES (p_key_id, p_nonce, v_now, v_expires)
  ON CONFLICT (key_id, nonce) DO UPDATE
    SET consumed_at = v_now,
        expires_at  = v_expires
    WHERE t.expires_at < v_now
  RETURNING true INTO v_first_use;

  RETURN COALESCE(v_first_use, false);
END;
$$;

REVOKE ALL ON FUNCTION public.consume_signer_nonce(text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.consume_signer_nonce(text, text, integer) FROM anon;
REVOKE ALL ON FUNCTION public.consume_signer_nonce(text, text, integer) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.consume_signer_nonce(text, text, integer) TO service_role;