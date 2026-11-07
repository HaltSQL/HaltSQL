open Haltsql_core
open Haltsql_load
open Helpers

let scalar_case (src, expected) =
  tc (Printf.sprintf "yaml scalar %S" src) (fun () ->
      let got = get_ok (yaml ("v: " ^ src)) in
      Alcotest.check json src (`Assoc [ ("v", expected) ]) got)

let scalars =
  [
    ("no", `String "no");
    ("No", `String "No");
    ("NO", `String "NO");
    ("yes", `String "yes");
    ("on", `String "on");
    ("off", `String "off");
    ("y", `String "y");
    ("n", `String "n");
    ("true", `Bool true);
    ("True", `Bool true);
    ("TRUE", `Bool true);
    ("false", `Bool false);
    ("False", `Bool false);
    ("FALSE", `Bool false);
    ("tRuE", `String "tRuE");
    ("~", `Null);
    ("null", `Null);
    ("Null", `Null);
    ("NULL", `Null);
    ("", `Null);
    ("nULL", `String "nULL");
    ("012", `String "012");
    ("-007", `String "-007");
    ("0", `Int 0);
    ("-0", `Int 0);
    ("+5", `Int 5);
    ("42", `Int 42);
    ("-17", `Int (-17));
    ("0x1F", `Int 31);
    ("0o17", `Int 15);
    ("0b101", `String "0b101");
    ("1_000", `String "1_000");
    ("0x", `String "0x");
    ("0xG1", `String "0xG1");
    ("1.5", `Float 1.5);
    ("-2e3", `Float (-2000.));
    (".5", `Float 0.5);
    ("1.", `Float 1.0);
    ("1e3", `Float 1000.);
    ("012.5", `String "012.5");
    ("99999999999999999999", `Intlit "99999999999999999999");
    ("\"true\"", `String "true");
    ("'no'", `String "no");
    ("\"012\"", `String "012");
    ("\"\"", `String "");
    ("'~'", `String "~");
    ("\"0x1F\"", `String "0x1F");
    ("2024-01-01", `String "2024-01-01");
    ("12:30", `String "12:30");
    ("hello world", `String "hello world");
    ("${ctx.tenant_id}", `String "${ctx.tenant_id}");
    ("|\n  multi\n  line", `String "multi\nline");
  ]

let yaml_errors =
  [
    tc "explicit !!str tag rejected" (fun () ->
        check_err ~path:"a" ~msg:"tags are not allowed" (yaml "a: !!str 1"));
    tc "custom tag rejected" (fun () ->
        check_err ~msg:"tags are not allowed" (yaml "a: !Ref foo"));
    tc "tag on mapping rejected" (fun () ->
        check_err ~msg:"tags are not allowed" (yaml "a: !!map {b: 1}"));
    tc "tag on sequence rejected" (fun () ->
        check_err ~msg:"tags are not allowed" (yaml "a: !!seq [1]"));
    tc "duplicate key rejected with location" (fun () ->
        let errs = get_err (yaml "a: 1\nb: 2\na: 3\n") in
        let e = List.hd errs in
        Alcotest.(check string) "path" "a" e.path;
        Alcotest.(check (option int)) "line" (Some 3) e.line;
        Alcotest.(check (option int)) "col" (Some 1) e.column;
        Alcotest.(check bool) "msg" true (contains e.message "first defined at line 1"));
    tc "nested duplicate key path" (fun () ->
        check_err ~path:"x.y" ~msg:"duplicate key" (yaml "x:\n  y: 1\n  y: 2\n"));
    tc "duplicate key quoted vs plain" (fun () ->
        check_err ~msg:"duplicate key" (yaml "a: 1\n\"a\": 2\n"));
    tc "multiple documents rejected" (fun () ->
        check_err ~msg:"multiple YAML documents" (yaml "---\na: 1\n---\nb: 2\n"));
    tc "explicit single document ok" (fun () -> ignore (get_ok (yaml "---\na: 1\n...\n")));
    tc "empty document is null" (fun () ->
        Alcotest.check json "null" `Null (get_ok (yaml "")));
    tc "comments only is null" (fun () ->
        Alcotest.check json "null" `Null (get_ok (yaml "# nothing\n")));
    tc "aliases expand" (fun () ->
        Alcotest.check json "alias"
          (`Assoc [ ("a", `List [ `Int 1 ]); ("b", `List [ `Int 1 ]) ])
          (get_ok (yaml "a: &x [1]\nb: *x\n")));
    tc "undefined alias" (fun () ->
        check_err ~msg:"undefined YAML alias" (yaml "a: *nope\n"));
    tc "alias as key rejected" (fun () ->
        check_err ~msg:"aliases cannot be used as mapping keys" (yaml "a: &k x\n*k : 1\n"));
    tc "complex key rejected" (fun () ->
        check_err ~msg:"mapping keys must be scalars" (yaml "? [a, b]\n: 1\n"));
    tc "billion laughs rejected quickly" (fun () ->
        let b = Buffer.create 4096 in
        Buffer.add_string b
          "a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n";
        let prev = ref "a" in
        List.iter
          (fun n ->
            Buffer.add_string b
              (Printf.sprintf "%s: &%s [%s]\n" n n
                 (String.concat "," (List.init 9 (fun _ -> "*" ^ !prev))));
            prev := n)
          [ "b"; "c"; "d"; "e"; "f"; "g"; "h"; "i" ];
        let t0 = Unix.gettimeofday () in
        check_err ~msg:"billion-laughs" (yaml (Buffer.contents b));
        Alcotest.(check bool) "fast" true (Unix.gettimeofday () -. t0 < 1.0));
    tc "moderate alias use allowed" (fun () ->
        ignore (get_ok (yaml "base: &b {x: 1, y: 2}\nc1: *b\nc2: *b\nc3: *b\n")));
    tc "depth 64 ok, 65 rejected" (fun () ->
        let nest n = String.make n '[' ^ String.make n ']' in
        ignore (get_ok (yaml (nest 64)));
        check_err ~msg:"nesting deeper than 64" (yaml (nest 65)));
    tc "too large rejected" (fun () ->
        let s = "a: \"" ^ String.make (Docload.max_document_bytes + 1) 'x' ^ "\"" in
        check_err ~msg:"limit is" (yaml s));
    tc ".inf rejected" (fun () -> check_err ~msg:"cannot be represented" (yaml "a: .inf"));
    tc "huge hex rejected" (fun () ->
        check_err ~msg:"out of range" (yaml "a: 0xFFFFFFFFFFFFFFFFFF"));
    tc "syntax error has location" (fun () ->
        let e = List.hd (get_err (yaml "a: 1\nb: [1, 2\nc: 3\n")) in
        Alcotest.(check bool) "msg" true (contains e.message "YAML syntax error");
        Alcotest.(check bool) "has line" true (e.line <> None));
    tc "tab indentation error" (fun () ->
        check_err ~msg:"YAML syntax error" (yaml "a:\n\t- b"));
    tc "integer keys become strings" (fun () ->
        Alcotest.check json "k"
          (`Assoc [ ("1", `String "x"); ("true", `Int 2) ])
          (get_ok (yaml "1: x\ntrue: 2\n")));
  ]

let json_cases =
  [
    tc "json basic" (fun () ->
        Alcotest.check json "v"
          (`Assoc
             [
               ( "a",
                 `List [ `Int 1; `Float 2.5; `Bool true; `Null; `String "x\n\xc3\xa9" ] );
             ])
          (get_ok (jsn {|{"a": [1, 2.5, true, null, "x\n\u00e9"]}|})));
    tc "json duplicate key rejected" (fun () ->
        let e = List.hd (get_err (jsn "{\n  \"a\": 1,\n  \"a\": 2\n}")) in
        Alcotest.(check string) "path" "a" e.path;
        Alcotest.(check (option int)) "line" (Some 3) e.line;
        Alcotest.(check (option int)) "col" (Some 3) e.column);
    tc "json nested duplicate" (fun () ->
        check_err ~path:"x[0].k" ~msg:"duplicate key" (jsn {|{"x":[{"k":1,"k":2}]}|}));
    tc "json syntax error location" (fun () ->
        let e = List.hd (get_err (jsn "{\n  \"a\": 1,\n  \"b\" 2\n}")) in
        Alcotest.(check (option int)) "line" (Some 3) e.line;
        Alcotest.(check (option int)) "col" (Some 7) e.column);
    tc "json trailing comma" (fun () ->
        check_err ~msg:"expected a string key" (jsn {|{"a":1,}|}));
    tc "json trailing content" (fun () ->
        check_err ~msg:"unexpected content" (jsn {|{} {}|}));
    tc "json leading zeros" (fun () ->
        check_err ~msg:"leading zeros" (jsn {|{"a": 012}|}));
    tc "json empty" (fun () -> check_err ~msg:"empty JSON document" (jsn "  "));
    tc "json control char" (fun () ->
        check_err ~msg:"control character" (jsn "{\"a\": \"x\001\"}"));
    tc "json surrogate pair" (fun () ->
        Alcotest.check json "emoji" (`String "\xf0\x9f\x98\x80")
          (get_ok (jsn {|"\ud83d\ude00"|})));
    tc "json lone surrogate" (fun () -> check_err ~msg:"surrogate" (jsn {|"\ud83d"|}));
    tc "json invalid utf8" (fun () ->
        check_err ~msg:"invalid UTF-8" (jsn "{\"a\": \"\xff\"}"));
    tc "json big int is intlit" (fun () ->
        Alcotest.check json "big" (`Intlit "123456789012345678901234567890")
          (get_ok (jsn "123456789012345678901234567890")));
    tc "json depth limit" (fun () ->
        let nest n = String.make n '[' ^ String.make n ']' in
        ignore (get_ok (jsn (nest 64)));
        check_err ~msg:"nesting deeper" (jsn (nest 65)));
    tc "json bom skipped" (fun () -> ignore (get_ok (jsn "\xef\xbb\xbf{\"a\":1}")));
    tc "json 1e999 rejected" (fun () -> check_err ~msg:"out of range" (jsn "1e999"));
  ]

let file_cases =
  [
    tc "format_of_path" (fun () ->
        Alcotest.(check bool)
          "yaml" true
          (Docload.format_of_path "a/b.yaml" = Some Docload.Yaml);
        Alcotest.(check bool)
          "yml" true
          (Docload.format_of_path "b.YML" = Some Docload.Yaml);
        Alcotest.(check bool)
          "json" true
          (Docload.format_of_path "b.json" = Some Docload.Json);
        Alcotest.(check bool) "none" true (Docload.format_of_path "b.toml" = None));
    tc "of_file missing" (fun () ->
        check_err ~msg:"cannot read file" (Docload.of_file "/nonexistent/x.yaml"));
    tc "of_file unknown extension" (fun () ->
        check_err ~msg:"cannot detect" (Docload.of_file "x.toml"));
    tc "of_file error carries file name" (fun () ->
        let f = Filename.temp_file "hs" ".yaml" in
        let oc = open_out f in
        output_string oc "a: 1\na: 2\n";
        close_out oc;
        let e = List.hd (get_err (Docload.of_file f)) in
        Alcotest.(check (option string)) "file" (Some f) e.file);
  ]

(* ---- printers and round-trip ---- *)

let tricky_strings =
  [
    "no";
    "yes";
    "on";
    "012";
    "true";
    "null";
    "~";
    "";
    "a: b";
    "- x";
    "#c";
    " lead";
    "trail ";
    "1.5";
    "0x1F";
    "@x";
    "`x";
    "!x";
    "&x";
    "*x";
    "|";
    ">";
    "%x";
    "'";
    "\"";
    "\\";
    "a\nb";
    "\t";
    "\x7f";
    "\xc2\x85";
    "\xe2\x80\xa8";
    "caf\xc3\xa9";
    "${ctx.tenant_id}";
    "key: value # c";
    "[a]";
    "{a}";
    "?";
    "-";
    ".inf";
    "1e3";
  ]

let printer_cases =
  [
    tc "yaml quotes retyped strings" (fun () ->
        List.iter
          (fun s ->
            let j = `Assoc [ (s, `String s) ] in
            Alcotest.check json s j (get_ok (yaml (Docload.to_string Docload.Yaml j))))
          tricky_strings);
    tc "yaml output is block style" (fun () ->
        let s =
          Docload.to_string Docload.Yaml
            (`Assoc [ ("a", `Assoc [ ("b", `List [ `Int 1; `String "no" ]) ]) ])
        in
        Alcotest.(check string) "yaml" "a:\n  b:\n    - 1\n    - \"no\"\n" s);
    tc "yaml empty containers" (fun () ->
        let j =
          `Assoc
            [ ("a", `Assoc []); ("b", `List []); ("c", `List [ `List []; `Assoc [] ]) ]
        in
        Alcotest.check json "empty" j (get_ok (yaml (Docload.to_string Docload.Yaml j))));
    tc "yaml long key" (fun () ->
        let k = String.make 2000 'k' in
        let j = `Assoc [ (k, `Assoc [ ("x", `Int 1) ]) ] in
        Alcotest.check json "long" j (get_ok (yaml (Docload.to_string Docload.Yaml j))));
    tc "json printer round trip" (fun () ->
        let j = `Assoc [ ("a", `List [ `Float 0.1; `Int (-3); `String "\"q\"" ]) ] in
        Alcotest.check json "json" j (get_ok (jsn (Docload.to_string Docload.Json j))));
    tc "convert example policy yaml->json->yaml" (fun () ->
        let j = get_ok (Docload.of_file (ex "policies/saas.yaml")) in
        let j2 = get_ok (jsn (Docload.to_string Docload.Json j)) in
        let j3 = get_ok (yaml (Docload.to_string Docload.Yaml j2)) in
        Alcotest.check json "same" j j3);
  ]

let gen_json : Yojson.Safe.t QCheck.Gen.t =
  let open QCheck.Gen in
  let str_gen =
    oneof
      [
        oneof_list tricky_strings;
        string_size
          ~gen:
            (oneof_list
               [
                 'a';
                 'Z';
                 '0';
                 ' ';
                 ':';
                 '#';
                 '-';
                 '"';
                 '\'';
                 '\n';
                 '\\';
                 '{';
                 '[';
                 '.';
                 '$';
                 '\x01';
               ])
          (0 -- 8);
        string_size ~gen:printable (0 -- 12);
      ]
  in
  let scalar =
    oneof
      [
        return `Null;
        map (fun b -> `Bool b) bool;
        map (fun i -> `Int i) int;
        map (fun i -> `Int i) int_small;
        map (fun f -> `Float f) (float_bound_inclusive 1e6);
        map
          (fun f -> `Float f)
          (oneof_list [ 0.1; 1e-300; 1e300; -0.5; 123456.789; 5e-324 ]);
        map (fun s -> `String s) str_gen;
      ]
  in
  sized_size (0 -- 4)
  @@ fix (fun self n ->
      if n = 0 then scalar
      else
        oneof_weighted
          [
            (2, scalar);
            (1, map (fun l -> `List l) (list_size (0 -- 4) (self (n - 1))));
            ( 1,
              map
                (fun kvs ->
                  let seen = Hashtbl.create 4 in
                  `Assoc
                    (List.filter
                       (fun (k, _) ->
                         if Hashtbl.mem seen k then false
                         else (
                           Hashtbl.add seen k ();
                           true))
                       kvs))
                (list_size (0 -- 4) (pair str_gen (self (n - 1)))) );
          ])

let arb_json = QCheck.make ~print:Yojson.Safe.to_string gen_json

let roundtrip fmt name =
  QCheck.Test.make ~count:1000 ~name arb_json (fun j ->
      match Docload.of_string fmt (Docload.to_string fmt j) with
      | Ok j' -> Yojson.Safe.equal j j'
      | Error e ->
          QCheck.Test.fail_reportf "%s\n---\n%s" (errs_to_string e)
            (Docload.to_string fmt j))

let props =
  List.map QCheck_alcotest.to_alcotest
    [
      roundtrip Docload.Yaml "yaml convert round-trip";
      roundtrip Docload.Json "json convert round-trip";
      QCheck.Test.make ~count:500 ~name:"yaml->json->yaml round-trip" arb_json (fun j ->
          let y = Docload.to_string Docload.Yaml j in
          let j1 = get_ok (yaml y) in
          let j2 = get_ok (jsn (Docload.to_string Docload.Json j1)) in
          Yojson.Safe.equal j j2);
    ]

let _ = Load_error.to_string

let tests =
  [
    ("yaml-core-schema", List.map scalar_case scalars);
    ("yaml-safety", yaml_errors);
    ("json", json_cases);
    ("files", file_cases);
    ("printers", printer_cases);
    ("roundtrip", props);
  ]
