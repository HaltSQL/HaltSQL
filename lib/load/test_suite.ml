(* Policy test-suite documents ([kind: TestSuite]); format in test_suite.mli. *)

open Haltsql_core

type expect = Allow | Deny

type case = {
  case_name : string;
  sql : string;
  context : Context.t;
  expect : expect;
  codes : Reason.code list;
  bind : (int * Context.value) list option;
  tags : string list;
}

type t = {
  suite_name : string;
  description : string option;
  policy_path : string;
  cases : case list;
}

let context_j ctx path j =
  match j with
  | `Assoc _ -> (
      match Context.of_json j with
      | Ok c -> Some c
      | Error e ->
          Dec.error ctx path e;
          None)
  | j ->
      Dec.type_error ctx path "a mapping of context values" j;
      None

let value_j ctx path j =
  match Context.of_json (`Assoc [ ("value", j) ]) with
  | Ok [ (_, v) ] -> Some v
  | Ok _ -> None
  | Error _ ->
      Dec.type_error ctx path "a string, integer, or list of those" j;
      None

let bind_j ctx path j =
  Dec.list_of ctx path
    (fun p x ->
      match Dec.obj ctx p ~keys:[ "param"; "value" ] x with
      | None -> None
      | Some kvs -> (
          let param =
            Dec.req ctx kvs p "param" (fun p v -> Dec.int ctx p ~min:1 ~max:65535 v)
          in
          let value = Dec.req ctx kvs p "value" (value_j ctx) in
          match (param, value) with Some n, Some v -> Some (n, v) | _ -> None))
    j

let code_j ctx path j =
  match Dec.string ctx path j with
  | None -> None
  | Some s -> (
      match Reason.code_of_string s with
      | Some c -> Some c
      | None ->
          Dec.error ctx path (Printf.sprintf "unknown reason code %S" s);
          None)

let case_j ctx path ~defaults j =
  match
    Dec.obj ctx path
      ~keys:[ "name"; "sql"; "expect"; "context"; "codes"; "bind"; "tags" ]
      j
  with
  | None -> None
  | Some kvs -> (
      let name = Dec.req ctx kvs path "name" (Dec.non_empty_string ctx) in
      let sql = Dec.req ctx kvs path "sql" (Dec.string ctx) in
      let expect =
        Dec.req ctx kvs path "expect"
          (Dec.enum ctx ~values:[ ("allow", Allow); ("deny", Deny) ])
      in
      let context =
        match Dec.field kvs "context" with
        | None -> Some defaults
        | Some v -> context_j ctx (Lpath.key path "context") v
      in
      let codes =
        Option.value ~default:[]
          (Dec.opt kvs path "codes" (fun p v -> Dec.list_of ctx p (code_j ctx) v))
      in
      let bind = Dec.opt kvs path "bind" (bind_j ctx) in
      let tags =
        Option.value ~default:[] (Dec.opt kvs path "tags" (Dec.string_list ctx))
      in
      if expect = Some Allow && codes <> [] then
        Dec.error ctx (Lpath.key path "codes")
          "codes can only be given when expect is deny";
      match (name, sql, expect, context) with
      | Some case_name, Some sql, Some expect, Some context ->
          Some { case_name; sql; context; expect; codes; bind; tags }
      | _ -> None)

let decode ctx ?base_dir path j =
  match
    Dec.obj ctx path
      ~keys:[ "apiVersion"; "kind"; "metadata"; "policy"; "defaults"; "cases" ]
      j
  with
  | None -> None
  | Some kvs -> (
      Dec.header ctx kvs path ~kind:"TestSuite";
      let meta =
        Dec.req ctx kvs path "metadata" (fun p v ->
            match Dec.obj ctx p ~keys:[ "name"; "description" ] v with
            | None -> None
            | Some m ->
                let name = Dec.req ctx m p "name" (Dec.non_empty_string ctx) in
                let desc = Dec.opt m p "description" (Dec.string ctx) in
                Option.map (fun n -> (n, desc)) name)
      in
      let policy =
        Dec.req ctx kvs path "policy" (fun p v ->
            Option.map (Dec.absolute ?base_dir) (Dec.non_empty_string ctx p v))
      in
      let defaults =
        match
          Dec.opt kvs path "defaults" (fun p v ->
              match Dec.obj ctx p ~keys:[ "context" ] v with
              | None -> None
              | Some d -> Dec.opt d p "context" (context_j ctx))
        with
        | Some c -> c
        | None -> Context.empty
      in
      let cases =
        Dec.req ctx kvs path "cases" (fun p v ->
            match Dec.list_of ctx p (fun p x -> case_j ctx p ~defaults x) v with
            | Some [] ->
                Dec.error ctx p "must contain at least one case";
                None
            | x -> x)
      in
      (match cases with
      | Some cs ->
          let seen = Hashtbl.create 16 in
          List.iteri
            (fun i c ->
              if Hashtbl.mem seen c.case_name then
                Dec.error ctx
                  (Lpath.idx (Lpath.key path "cases") i)
                  (Printf.sprintf "duplicate case name %S" c.case_name)
              else Hashtbl.add seen c.case_name ())
            cs
      | None -> ());
      match (meta, policy, cases) with
      | Some (suite_name, description), Some policy_path, Some cases ->
          Some { suite_name; description; policy_path; cases }
      | _ -> None)

let of_json_pos ?file ?base_dir ?positions j =
  let ctx = Dec.create ?file ?positions () in
  let base_dir = Dec.base_dir_of ?base_dir file in
  match decode ctx ?base_dir Lpath.root j with
  | Some t when not (Dec.has_errors ctx) -> Ok t
  | _ -> Error (Dec.errors ctx)

let of_json ?file ?base_dir j = of_json_pos ?file ?base_dir j

let of_file file =
  match Docpos.parse_file file with
  | Error e -> Error e
  | Ok (j, positions) -> of_json_pos ~file ~base_dir:(Filename.dirname file) ~positions j
