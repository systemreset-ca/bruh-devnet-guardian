-- Durable nonce store SQL tests (V2 routine).
--
-- Scope: single database session. Covers first use, replay, replay while the
-- row still has time remaining, fixed-300s retention, key/nonce format
-- constraints, server-clock expiry, expired-row reclaim, bounded cleanup,
-- role ACLs (including PUBLIC) and the routine's search_path.
-- The "sequential" race check below is NOT real concurrency; real
-- multi-session concurrency is covered by scripts/nonce-concurrency-test.ts.
DROP TABLE IF EXISTS signer_nonce_test_results;
CREATE TEMP TABLE signer_nonce_test_results (ord serial, test text, pass boolean, note text);

DO $$
DECLARE
  v_pass boolean;
  v_expires timestamptz;
  v_wins integer;
  v_n1 text := 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
  v_n2 text := 'b1b2c3d4e5f60718293a4b5c6d7e8f91';
  v_n3 text := 'c1b2c3d4e5f60718293a4b5c6d7e8f92';
  v_n4 text := 'd1b2c3d4e5f60718293a4b5c6d7e8f93';
  v_n5 text := 'e1b2c3d4e5f60718293a4b5c6d7e8f94';
BEGIN
  -- first use / replay
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('first_use_returns_true',
          public.consume_signer_nonce('signer-key-tst', v_n1, 300) IS TRUE, 'single session');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('replay_returns_false',
          public.consume_signer_nonce('signer-key-tst', v_n1, 300) IS FALSE, 'single session');

  -- expiry comes from the server clock with fixed 300s retention
  SELECT expires_at INTO v_expires FROM public.signer_nonces
   WHERE key_id = 'signer-key-tst' AND nonce = v_n1;
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('expiry_uses_server_clock_fixed_300s',
          v_expires > now() + interval '290 seconds'
      AND v_expires <= now() + interval '300 seconds', 'no client clock accepted');

  -- a row with time remaining is never reclaimable (replay still rejected)
  UPDATE public.signer_nonces SET expires_at = now() + interval '2 seconds'
   WHERE key_id = 'signer-key-tst' AND nonce = v_n1;
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('replay_with_2s_remaining_rejected',
          public.consume_signer_nonce('signer-key-tst', v_n1, 300) IS FALSE,
          'live row not reclaimable');

  -- expired row is reclaimable exactly once
  UPDATE public.signer_nonces SET expires_at = now() - interval '1 second'
   WHERE key_id = 'signer-key-tst' AND nonce = v_n1;
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('expired_row_reclaimed_once',
          public.consume_signer_nonce('signer-key-tst', v_n1, 300) IS TRUE
      AND public.consume_signer_nonce('signer-key-tst', v_n1, 300) IS FALSE, 'expiry window');

  -- key id constraints
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('accept_single_char_key_id',
          public.consume_signer_nonce('k', v_n2, 300) IS TRUE, 'regex allows 1-64 chars');

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce(repeat('k', 65), v_n3, 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_key_id_over_64_chars', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('bad key id!!', v_n3, 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_key_id_charset', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce(NULL, v_n3, 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_null_key_id', v_pass);

  -- nonce constraints: canonical lowercase hex, 32-64 chars
  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', repeat('a', 31), 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_nonce_under_32_chars', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', repeat('a', 65), 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_nonce_over_64_chars', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', upper(v_n3), 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_uppercase_nonce', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', 'zzzz2c3d4e5f60718293a4b5c6d7e8f9', 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_non_hex_nonce', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', NULL, 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_null_nonce', v_pass);

  -- fixed retention: anything other than 300 is rejected
  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', v_n4, 1);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('reject_ttl_1', v_pass, 'short TTL would permit replay inside skew window');

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', v_n4, 60);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_ttl_60', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', v_n4, 299);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_ttl_299', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', v_n4, 301);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_ttl_301', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', v_n4, 0);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_ttl_zero', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', v_n4, -1);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_ttl_negative', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer-key-tst', v_n4, NULL);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_null_ttl', v_pass);

  -- bounded cleanup of expired rows
  INSERT INTO public.signer_nonces (key_id, nonce, expires_at)
  SELECT 'signer-key-cln', md5('cleanup-' || g::text), now() - interval '1 minute'
    FROM generate_series(1, 50) g;
  PERFORM public.consume_signer_nonce('signer-key-tst', v_n4, 300);
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('expired_rows_cleaned_up',
          (SELECT count(*) FROM public.signer_nonces WHERE key_id = 'signer-key-cln') = 0,
          'bounded at 200 rows per call');

  -- sequential double attempt in ONE session (not concurrency)
  SELECT count(*) INTO v_wins FROM (
    SELECT public.consume_signer_nonce('signer-key-tst', v_n5, 300) AS r
    UNION ALL
    SELECT public.consume_signer_nonce('signer-key-tst', v_n5, 300)
  ) s WHERE r;
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('sequential_same_nonce_one_winner', v_wins = 1, 'SINGLE SESSION ONLY - not real concurrency');

  -- table ACLs: PUBLIC and every Data API role are denied
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('public_has_no_table_privileges',
          NOT has_table_privilege('public', 'public.signer_nonces', 'SELECT')
      AND NOT has_table_privilege('public', 'public.signer_nonces', 'INSERT')
      AND NOT has_table_privilege('public', 'public.signer_nonces', 'UPDATE')
      AND NOT has_table_privilege('public', 'public.signer_nonces', 'DELETE'), 'ACL');

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

  -- routine ACLs
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('public_cannot_execute_routine',
          NOT has_function_privilege('public', 'public.consume_signer_nonce(text,text,integer)', 'EXECUTE'), 'ACL');

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

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('routine_search_path_is_pg_catalog',
          (SELECT proconfig @> ARRAY['search_path=pg_catalog'] FROM pg_proc
            WHERE oid = 'public.consume_signer_nonce(text,text,integer)'::regprocedure),
          'pg_temp cannot shadow');

  -- clean up test rows
  DELETE FROM public.signer_nonces WHERE key_id IN ('signer-key-tst', 'signer-key-cln', 'signer-key-cnc', 'k');
END $$;

SELECT test, pass, coalesce(note, '') AS note FROM signer_nonce_test_results ORDER BY ord;
SELECT count(*) FILTER (WHERE pass) AS passed,
       count(*) FILTER (WHERE NOT pass OR pass IS NULL) AS failed
  FROM signer_nonce_test_results;
