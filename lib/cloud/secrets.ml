open Lwt.Infix
module Config = Haltsql_load.Config

type t = {
  secrets : Config.secrets;
  env : string -> string option;
  now : unit -> float;
  timeout : float;
  aws_credentials : Aws_creds.t option;
  gcp_auth : Gcp_auth.t option;
  cache : (string * string, (string, string) result) Hashtbl.t;
  inflight : (string * string, (string, string) result Lwt.t) Hashtbl.t;
  mutable fetches : int;
  mutable vault : Vault.t option;
  mutable aws : Aws_sm.t option;
  mutable gcp : Gcp_sm.t option;
}

let create ?(env = Sys.getenv_opt) ?(now = Unix.gettimeofday) ?(timeout = 10.)
    ?aws_credentials ?gcp_auth secrets =
  {
    secrets;
    env;
    now;
    timeout;
    aws_credentials;
    gcp_auth;
    cache = Hashtbl.create 8;
    inflight = Hashtbl.create 8;
    fetches = 0;
    vault = None;
    aws = None;
    gcp = None;
  }

let fetch_count t = t.fetches

let fetch t ~scheme ~reference =
  match scheme with
  | "vault" -> (
      match (t.vault, t.secrets.vault) with
      | Some v, _ -> Vault.read v reference
      | None, Some cfg ->
          let v = Vault.create ~now:t.now ~timeout:t.timeout cfg in
          t.vault <- Some v;
          Vault.read v reference
      | None, None -> Lwt.return (Error "secrets.vault is not configured"))
  | "aws-sm" -> (
      match (t.aws, t.secrets.aws) with
      | Some a, _ -> Aws_sm.get a reference
      | None, Some cfg ->
          let a =
            Aws_sm.create ~env:t.env ~now:t.now ~timeout:t.timeout
              ?credentials:t.aws_credentials cfg
          in
          t.aws <- Some a;
          Aws_sm.get a reference
      | None, None -> Lwt.return (Error "secrets.aws is not configured"))
  | "gcp-sm" ->
      let cfg =
        Option.value
          ~default:{ Config.gcp_project = None; gcp_endpoint = None }
          t.secrets.gcp
      in
      let g =
        match t.gcp with
        | Some g -> g
        | None ->
            let g =
              Gcp_sm.create ~env:t.env ~now:t.now ~timeout:t.timeout ?auth:t.gcp_auth cfg
            in
            t.gcp <- Some g;
            g
      in
      Gcp_sm.get g reference
  | s -> Lwt.return (Error (Printf.sprintf "unknown secret provider %S" s))

let resolve t ~scheme ~reference =
  let k = (scheme, reference) in
  match Hashtbl.find_opt t.cache k with
  | Some r -> Lwt.return r
  | None -> (
      match Hashtbl.find_opt t.inflight k with
      | Some p -> p
      | None ->
          t.fetches <- t.fetches + 1;
          let p =
            Lwt.catch
              (fun () -> fetch t ~scheme ~reference)
              (fun e -> Lwt.return (Error ("internal error: " ^ Printexc.to_string e)))
            >|= fun r ->
            Hashtbl.remove t.inflight k;
            Hashtbl.replace t.cache k r;
            r
          in
          if Lwt.state p = Lwt.Sleep then Hashtbl.replace t.inflight k p;
          p)

let provider_schemes = [ "vault"; "aws-sm"; "gcp-sm" ]

let scan_placeholders s =
  let n = String.length s in
  let acc = ref [] in
  let rec go i =
    if i + 1 >= n then ()
    else if i + 2 < n && s.[i] = '$' && s.[i + 1] = '$' && s.[i + 2] = '{' then go (i + 3)
    else if s.[i] = '$' && s.[i + 1] = '{' then (
      match String.index_from_opt s (i + 2) '}' with
      | None -> ()
      | Some j ->
          let inner = String.sub s (i + 2) (j - i - 2) in
          (match String.index_opt inner ':' with
          | Some k ->
              let sc = String.sub inner 0 k
              and r = String.sub inner (k + 1) (String.length inner - k - 1) in
              if List.mem sc provider_schemes && not (List.mem (sc, r) !acc) then
                acc := (sc, r) :: !acc
          | None -> ());
          go (j + 1))
    else go (i + 1)
  in
  go 0;
  List.rev !acc

let prefetch t refs =
  Lwt.join
    (List.map (fun (scheme, reference) -> resolve t ~scheme ~reference >|= ignore) refs)

let cached_resolver t ~scheme ~reference =
  match Hashtbl.find_opt t.cache (scheme, reference) with
  | Some r -> r
  | None ->
      Error
        "secret was not prefetched (placeholder not found verbatim in the config file)"

let blocking_resolver t ~scheme ~reference =
  match Hashtbl.find_opt t.cache (scheme, reference) with
  | Some r -> r
  | None -> Lwt_main.run (resolve t ~scheme ~reference)

let load_config ?(env = Sys.getenv_opt) ?timeout file =
  match Config.secrets_of_file ~env file with
  | Error e -> Lwt.return (Error e)
  | Ok secrets -> (
      let t = create ~env ?timeout secrets in
      match In_channel.with_open_bin file In_channel.input_all with
      | exception Sys_error _ ->
          Lwt.return (Config.of_file ~env ~resolve:(cached_resolver t) file)
      | text ->
          prefetch t (scan_placeholders text) >|= fun () ->
          Config.of_file ~env ~resolve:(cached_resolver t) file)

let load_config_blocking ?env ?timeout file =
  Lwt_main.run (load_config ?env ?timeout file)
