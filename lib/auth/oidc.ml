(** Pure OIDC token verification. *)

module Config = Haltsql.Config
module Context = Haltsql.Context

type identity = {
  provider : string;
  issuer : string;
  subject : string option;
  policy : string;
  context : Context.t;
  request_context_fields : string list;
  expires_at : float;
  matched_group : string option;
}

let ( let* ) = Result.bind
let lookup_claim = Group_policy.lookup_claim

(* 2^53: integers beyond this are not exactly representable as floats. *)
let max_exact = 9007199254740992.

let scalar_string : Yojson.Safe.t -> string option = function
  | `String s -> Some s
  | `Int i -> Some (string_of_int i)
  | `Intlit s -> Some s
  | `Float f when Float.is_integer f && Float.abs f <= max_exact ->
      Some (Printf.sprintf "%.0f" f)
  | _ -> None

let context_value (j : Yojson.Safe.t) : Context.value option =
  match j with
  | `List [] -> None
  | `List items ->
      let vs = List.filter_map scalar_string items in
      if List.length vs = List.length items then Some (Context.Many vs) else None
  | j -> Option.map (fun s -> Context.One s) (scalar_string j)

let one_matches ~name (claim : Yojson.Safe.t) v =
  match claim with
  | `String s ->
      String.equal s v
      || (name = "scope" || name = "scp")
         && List.mem v (List.filter (( <> ) "") (String.split_on_char ' ' s))
  | `List items -> List.exists (fun i -> scalar_string i = Some v) items
  | `Bool b -> string_of_bool b = v
  | j -> scalar_string j = Some v

let claim_matches ?(name = "") claim = function
  | Config.Claim_one v -> one_matches ~name claim v
  | Config.Claim_all vs -> List.for_all (one_matches ~name claim) vs

let check_time (p : Config.oidc_provider) ~now claims =
  let leeway = float_of_int p.leeway_seconds in
  let* exp = Jwt.number_claim "exp" claims in
  let* nbf = Jwt.number_claim "nbf" claims in
  let* iat = Jwt.number_claim "iat" claims in
  match exp with
  | None -> Error (Jwt.Missing_claim "exp")
  | Some exp ->
      if now >= exp +. leeway then Error Jwt.Expired
      else if match nbf with Some n -> now +. leeway < n | None -> false then
        Error Jwt.Not_yet_valid
      else if match iat with Some i -> now +. leeway < i | None -> false then
        Error Jwt.Issued_in_future
      else Ok exp

let check_audience (p : Config.oidc_provider) claims =
  let ok a = List.mem a p.audiences in
  match List.assoc_opt "aud" claims with
  | Some (`String a) when ok a -> Ok ()
  | Some (`List l) when List.exists (function `String a -> ok a | _ -> false) l -> Ok ()
  | _ -> Error Jwt.Wrong_audience

let rec all_ok f = function
  | [] -> Ok ()
  | x :: xs ->
      let* () = f x in
      all_ok f xs

let verify ?groups (p : Config.oidc_provider) ~keys ~now tok =
  let* t = Jwt.decode tok in
  let* alg = Jwt.alg_of_string t.alg_name in
  if not (List.mem alg p.algorithms) then Error (Jwt.Alg_not_allowed t.alg_name)
  else
    let* key = Jwt.select_key alg ~kid:t.kid keys in
    if
      not
        (Jwt.verify_signature alg key.key ~signing_input:t.signing_input
           ~signature:t.signature)
    then Error Jwt.Bad_signature
    else
      let* () =
        match List.assoc_opt "iss" t.claims with
        | Some (`String i) when i = p.issuer -> Ok ()
        | _ -> Error Jwt.Wrong_issuer
      in
      let* () = check_audience p t.claims in
      let* expires_at = check_time p ~now t.claims in
      let* () =
        all_ok
          (fun (name, m) ->
            match lookup_claim t.claims name with
            | None -> Error (Jwt.Missing_claim name)
            | Some c ->
                if claim_matches ~name c m then Ok () else Error (Jwt.Claim_mismatch name))
          p.required_claims
      in
      let* policy, matched_group =
        match (groups, p.oidc_policy) with
        | Some g, _ ->
            let* s = Group_policy.select g t.claims in
            Ok (s.policy, s.matched_group)
        | None, Config.Oidc_pinned n -> Ok (n, None)
        | None, Config.Oidc_from_claim { claim; allowed } -> (
            match lookup_claim t.claims claim with
            | None -> Error (Jwt.Missing_claim claim)
            | Some (`String n) when List.mem n allowed -> Ok (n, None)
            | Some _ -> Error (Jwt.Policy_not_allowed claim))
      in
      let* context =
        List.fold_left
          (fun acc (field, path) ->
            let* acc = acc in
            match lookup_claim t.claims path with
            | None -> Error (Jwt.Missing_claim path)
            | Some j -> (
                match context_value j with
                | Some v -> Ok ((field, v) :: acc)
                | None -> Error (Jwt.Bad_claim path)))
          (Ok []) p.context_claims
      in
      let subject =
        match List.assoc_opt "sub" t.claims with Some (`String s) -> Some s | _ -> None
      in
      Ok
        {
          provider = p.oidc_name;
          issuer = p.issuer;
          subject;
          policy;
          context = List.rev context;
          request_context_fields = p.oidc_request_context_fields;
          expires_at;
          matched_group;
        }
