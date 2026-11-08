let () =
  Alcotest.run "haltsql.load"
    (T_docload.tests @ T_policy.tests @ T_config.tests @ T_config_ext.tests
   @ T_config_tier3.tests @ T_misc.tests)
