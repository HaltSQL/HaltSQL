let () =
  Alcotest.run "haltsql.load"
    (T_docload.tests @ T_policy.tests @ T_config.tests @ T_misc.tests)
