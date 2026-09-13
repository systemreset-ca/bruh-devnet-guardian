-- Durable nonce store SQL tests.
--
-- Scope: single database session. Covers first use, replay, format/TTL
-- constraints, server-clock expiry, expired-row reclaim, bounded cleanup and
-- role ACLs. The "sequential" race check below is NOT real concurrency;
-- real multi-session concurrency is covered by scripts/nonce-concurrency-test.ts.
DROP TABLE IF EXISTS signer_nonce_test_results;
CREATE TEMP TABLE signer_nonce_test_results (ord serial, test text, pass boolean, note text);

DO $$
DECLARE
  v_pass boolean;
  v_expires timestamptz;
  v_wins integer;
BEGIN
  -- first use / replay
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('first_use_returns_true',
          public.consume_signer_nonce('signer-key-tst', 'nonce_first_use_0001', 60) IS TRUE, 'single session');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('replay_returns_false',
          public.consume_signer_nonce('signer-key-tst', 'nonce_first_use_0001', 60) IS FALSE, 'single session');

  -- expiry is set from the server clock and bounded by the requested TTL
  SELECT expires_at INTO v_expires FROM public.signer_nonces
   WHERE key_id = 'signer-key-tst' AND nonce = 'nonce_first_use_0001';
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('expiry_uses_server_clock',
          v_expires > now() AND v_expires <= now() + interval '60 seconds', 'no client clock accepted');

  -- expired row is reclaimable exactly once
  UPDATE public.signer_nonces SET expires_at = now() - interval '1 second'
   WHERE key_id = 'signer-key-tst' AND nonce = 'nonce_first_use_0001';
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('expired_row_reclaimed_once',
          public.consume_signer_nonce('signer-key-tst', 'nonce_first_use_0001', 60) IS TRUE
      AND public.consume_signer_nonce('signer-key-tst', 'nonce_first_use_0001', 60) IS FALSE, 'expiry window');

  -- constraint rejections
  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('short', 'nonce_valid_00000001', 60);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_short_key_id', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('bad key id!!', 'nonce_valid_00000001', 60);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_key_id_charset', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', 'tooshort', 60);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_short_nonce', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', 'nonce with spaces!!!!', 60);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_nonce_charset', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', NULL, 60);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_null_nonce', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', 'nonce_ttl_zero_000001', 0);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_zero_ttl', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', 'nonce_ttl_long_000001', 3600);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_long_ttl_over_300s', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', 'nonce_ttl_null_000001', NULL);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_null_ttl', v_pass);

  -- bounded cleanup of expired rows
  INSERT INTO public.signer_nonces (key_id, nonce, expires_at)
  SELECT 'signer-key-cln', 'nonce_cleanup_' || lpad(g::text, 8, '0'), now() - interval '1 minute'
    FROM generate_series(1, 50) g;
  PERFORM public.consume_signer_nonce('signer-key-tst', 'nonce_cleanup_trigger1', 60);
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('expired_rows_cleaned_up',
          (SELECT count(*) FROM public.signer_nonces WHERE key_id = 'signer-key-cln') = 0,
          'bounded at 200 rows per call');

  -- sequential double attempt in ONE session (not concurrency)
  SELECT count(*) INTO v_wins FROM (
    SELECT public.consume_signer_nonce('signer-key-tst', 'nonce_seq_race_000001', 60) AS r
    UNION ALL
    SELECT public.consume_signer_nonce('signer-key-tst', 'nonce_seq_race_000001', 60)
  ) s WHERE r;
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('sequential_same_nonce_one_winner', v_wins = 1, 'SINGLE SESSION ONLY - not real concurrency');

  -- role ACLs: no Data API role may touch the table or call the routine
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('anon_has_no_table_privileges',
          NOT has_table_privilege('anon', 'public.signer_nonces', 'SELECT')
      AND NOT has_table_privilege('anon', 'public.signer_nonces', 'INSERT')
      AND NOT has_table_privilege('anon', 'public.signer_nonces', 'UPDATE')
      AND NOT has_table_privilege('anon', 'public.signer_nonces', 'DELETE'), 'ACL');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('authenticated_has_no_table_privileges',
          NOT has_table_privilege('authenticated', 'public.signer_nonces', 'SELECT')
      AND NOT has_table_privilege('authenticated', 'public.signer_nonces', 'INSERT')
      AND NOT has_table_privilege('authenticated', 'public.signer_nonces', 'UPDATE')
      AND NOT has_table_privilege('authenticated', 'public.signer_nonces', 'DELETE'), 'ACL');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('service_role_has_no_table_privileges',
          NOT has_table_privilege('service_role', 'public.signer_nonces', 'SELECT')
      AND NOT has_table_privilege('service_role', 'public.signer_nonces', 'INSERT')
      AND NOT has_table_privilege('service_role', 'public.signer_nonces', 'UPDATE')
      AND NOT has_table_privilege('service_role', 'public.signer_nonces', 'DELETE'),
          'direct writes denied even for the server role');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('rls_enabled_and_forced',
          (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
            WHERE oid = 'public.signer_nonces'::regclass), 'RLS');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('all_policies_deny',
          (SELECT count(*) FROM pg_policies
            WHERE schemaname = 'public' AND tablename = 'signer_nonces') = 4
      AND NOT EXISTS (SELECT 1 FROM pg_policies
            WHERE schemaname = 'public' AND tablename = 'signer_nonces'
              AND coalesce(qual, 'false') <> 'false'
              AND coalesce(with_check, 'false') <> 'false'), 'deny-all policies');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('anon_cannot_execute_routine',
          NOT has_function_privilege('anon', 'public.consume_signer_nonce(text,text,integer)', 'EXECUTE'), 'ACL');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('authenticated_cannot_execute_routine',
          NOT has_function_privilege('authenticated', 'public.consume_signer_nonce(text,text,integer)', 'EXECUTE'), 'ACL');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('service_role_can_execute_routine',
          has_function_privilege('service_role', 'public.consume_signer_nonce(text,text,integer)', 'EXECUTE'),
          'only access path');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('routine_is_security_definer',
          (SELECT prosecdef FROM pg_proc WHERE oid = 'public.consume_signer_nonce(text,text,integer)'::regprocedure), 'ACL');

  -- clean up test rows
  DELETE FROM public.signer_nonces WHERE key_id IN ('signer-key-tst', 'signer-key-cln', 'signer-key-cnc');
END $$;

SELECT test, pass, coalesce(note, '') AS note FROM signer_nonce_test_results ORDER BY ord;
SELECT count(*) FILTER (WHERE pass) AS passed,
       count(*) FILTER (WHERE NOT pass OR pass IS NULL) AS failed
  FROM signer_nonce_test_results;
