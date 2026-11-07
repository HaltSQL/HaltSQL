let () = Alcotest.run "analyzer" (Test_ast.suites @ Test_sql.suites @ Test_policies.suites)
