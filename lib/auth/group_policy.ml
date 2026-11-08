(* policy_from_groups: IdP groups -> policy, first match wins. *)

module Config = Haltsql.Config

type selection = { policy : string; matched_group : string option; groups : string list }

let ( let* ) = Result.bind

let lookup_claim claims path =
  match List.assoc_opt path claims with
  | Some v -> Some v
  | None ->
      let rec walk (j : Yojson.Safe.t) = function
        | [] -> Some j
        | k :: rest -> (
            match j with
            | `Assoc kv -> (
                match List.assoc_opt k kv with Some v -> walk v rest | None -> None)
            | _ -> None)
      in
      let parts = String.split_on_char '.' path in
      if List.length parts < 2 || List.mem "" parts then None
      else walk (`Assoc claims) parts

let first_segment claim =
  match String.index_opt claim '.' with Some i -> String.sub claim 0 i | None -> claim

let overage ~claim claims =
  let names = [ claim; first_segment claim ] in
  let by_claim_names =
    match List.assoc_opt "_claim_names" claims with
    | None -> false
    | Some (`Assoc kv) -> List.exists (fun (k, _) -> List.mem k names) kv
    | Some _ -> true
  in
  let by_hasgroups =
    List.mem "groups" names
    &&
    match List.assoc_opt "hasgroups" claims with
    | Some (`Bool true) | Some (`String "true") -> true
    | _ -> false
  in
  by_claim_names || by_hasgroups

let groups (g : Config.groups_policy) claims =
  let claim = g.groups_claim in
  if overage ~claim claims then Error (Jwt.Groups_overage claim)
  else
    match lookup_claim claims claim with
    | None -> Error (Jwt.Missing_claim claim)
    | Some v -> (
        match Config.groups_of_claim v with
        | Some gs -> Ok gs
        | None -> Error (Jwt.Bad_claim claim))

let select (g : Config.groups_policy) claims =
  let* gs = groups g claims in
  match
    List.find_opt (fun (r : Config.group_rule) -> List.mem r.group gs) g.group_rules
  with
  | Some r -> Ok { policy = r.group_policy; matched_group = Some r.group; groups = gs }
  | None -> (
      match g.group_default with
      | Some p -> Ok { policy = p; matched_group = None; groups = gs }
      | None -> Error (Jwt.No_group_policy g.groups_claim))

let resolve g claims =
  let* s = select g claims in
  Ok s.policy
