(** Authenticated context + permitted request-body context. *)

module Context = Haltsql.Context

let merge ~(authenticated : Context.t) ~allowed ~(body : Context.t) =
  let refused =
    List.filter_map
      (fun (k, v) ->
        match List.assoc_opt k authenticated with
        | Some v' when v' = v -> None
        | Some _ -> Some k
        | None -> if List.mem k allowed then None else Some k)
      body
  in
  if refused <> [] then Error refused
  else
    let extra =
      List.filter
        (fun (k, _) -> List.mem k allowed && not (List.mem_assoc k authenticated))
        body
    in
    Ok (authenticated @ extra)
