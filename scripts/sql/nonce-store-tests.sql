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
          public.consume_signer_nonce('signer.key-tst', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 300) IS TRUE, 'single session');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('replay_returns_false',
          public.consume_signer_nonce('signer.key-tst', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 300) IS FALSE, 'single session');

  -- expiry is set from the server clock and bounded by the requested TTL
  SELECT expires_at INTO v_expires FROM public.signer_nonces
   WHERE key_id = 'signer.key-tst' AND nonce = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('expiry_uses_server_clock',
          v_expires > now() AND v_expires <= now() + interval '300 seconds', 'no client clock accepted');

  -- expired row is reclaimable exactly once
  UPDATE public.signer_nonces SET expires_at = now() - interval '1 second'
   WHERE key_id = 'signer.key-tst' AND nonce = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('expired_row_reclaimed_once',
          public.consume_signer_nonce('signer.key-tst', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 300) IS TRUE
      AND public.consume_signer_nonce('signer.key-tst', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 300) IS FALSE, 'expiry window');

  -- constraint rejections
  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('short', 'aaaabbbbccccddddeeeeffff00001111', 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_short_key_id', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('bad key id!!', 'aaaabbbbccccddddeeeeffff00001111', 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_key_id_charset', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer.key-tst', 'abcd', 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_short_nonce', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer.key-tst', 'A1B2C3D4E5F60718293A4B5C6D7E8F90', 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_uppercase_hex_nonce', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer.key-tst', NULL, 300);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_null_nonce', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer.key-tst', '99887766554433221100ffeeddccbbaa', 0);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_zero_ttl', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer.key-tst', '1234567890abcdef1234567890abcdef', 3600);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_ttl_other_than_300', v_pass);

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer.key-tst', 'fedcba0987654321fedcba0987654321', NULL);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass) VALUES ('reject_null_ttl', v_pass);

  -- bounded cleanup of expired rows
  INSERT INTO public.signer_nonces (key_id, nonce, expires_at)
  SELECT 'signer.key-cln', lpad(to_hex(g), 32, '0'), now() - interval '1 minute'
    FROM generate_series(1, 50) g;
  PERFORM public.consume_signer_nonce('signer.key-tst', '11223344556677889900aabbccddeeff', 300);
  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('expired_rows_cleaned_up',
          (SELECT count(*) FROM public.signer_nonces WHERE key_id = 'signer.key-cln') = 0,
          'bounded at 200 rows per call');

  -- sequential double attempt in ONE session (not concurrency)
  SELECT count(*) INTO v_wins FROM (
    SELECT public.consume_signer_nonce('signer.key-tst', '0f1e2d3c4b5a69788796a5b4c3d2e1f0', 300) AS r
    UNION ALL
    SELECT public.consume_signer_nonce('signer.key-tst', '0f1e2d3c4b5a69788796a5b4c3d2e1f0', 300)
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

  -- Retention must outlive the verifier's 60-second timestamp window: with only
  -- 2 seconds of that window left, the nonce row must still be live and the
  -- replay must be refused.
  PERFORM public.consume_signer_nonce('signer.key-tst', 'cafebabecafebabecafebabecafebabe', 300);
  INSERT INTO signer_nonce_test_results (test, pass, note)
  SELECT 'replay_rejected_with_2s_of_window_left',
         sn.expires_at > now() + interval '58 seconds'
           AND public.consume_signer_nonce('signer.key-tst', 'cafebabecafebabecafebabecafebabe', 300) IS FALSE,
         'fixed 300s retention'
    FROM public.signer_nonces sn
   WHERE sn.key_id = 'signer.key-tst' AND sn.nonce = 'cafebabecafebabecafebabecafebabe';

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer.key-tst', 'deadbeefdeadbeefdeadbeefdeadbeef', 60);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass, note) VALUES ('reject_ttl_60', v_pass, 'only 300 accepted');

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer.key-tst', 'deadbeefdeadbeefdeadbeefdeadbee1', 299);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass, note) VALUES ('reject_ttl_299', v_pass, 'only 300 accepted');

  BEGIN v_pass := false; PERFORM public.consume_signer_nonce('signer.key-tst', 'deadbeefdeadbeefdeadbeefdeadbee2', 301);
  EXCEPTION WHEN others THEN v_pass := true; END;
  INSERT INTO signer_nonce_test_results (test, pass, note) VALUES ('reject_ttl_301', v_pass, 'only 300 accepted');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('public_role_has_no_table_privileges',
          NOT (has_table_privilege('public', 'public.signer_nonces', 'SELECT')
            OR has_table_privilege('public', 'public.signer_nonces', 'INSERT')
            OR has_table_privilege('public', 'public.signer_nonces', 'UPDATE')
            OR has_table_privilege('public', 'public.signer_nonces', 'DELETE')), 'ACL');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('public_role_cannot_execute_routine',
          NOT has_function_privilege('public', 'public.consume_signer_nonce(text,text,integer)', 'EXECUTE'), 'ACL');

  INSERT INTO signer_nonce_test_results (test, pass, note)
  VALUES ('routine_search_path_is_pg_catalog',
          (SELECT 'search_path=pg_catalog' = ANY (coalesce(proconfig, ARRAY[]::text[]))
             FROM pg_proc WHERE oid = 'public.consume_signer_nonce(text,text,integer)'::regprocedure),
          'no pg_temp shadowing');

  -- clean up test rows
  DELETE FROM public.signer_nonces WHERE key_id IN ('signer.key-tst', 'signer.key-cln', 'signer.key-cnc');
END $$;

SELECT test, pass, coalesce(note, '') AS note FROM signer_nonce_test_results ORDER BY ord;
SELECT count(*) FILTER (WHERE pass) AS passed,
       count(*) FILTER (WHERE NOT pass OR pass IS NULL) AS failed
  FROM signer_nonce_test_results;
