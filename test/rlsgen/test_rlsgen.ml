let () =
  (* probe Postgres before Alcotest captures output, so a skip is visible *)
  ignore (Lazy.force T_integration.available);
  Alcotest.run "rlsgen" [ ("unit", T_unit.tests); ("integration", T_integration.tests) ]
