type record = Record.t

let of_audit_fields fields =
  match Record.of_json (`Assoc fields) with Ok r -> Some r | Error _ -> None

let of_verdict ~ts ~caller ~caller_type ~sql v =
  Record.of_verdict ~ts ~caller ~caller_type ~sql v

let policy (r : record) = r.policy
let fingerprint = Record.fingerprint_key
let has_sql (r : record) = r.sql <> None
let strip_sql (r : record) = { r with sql = None }
let parse_since = Rtime.parse_bound

let enrich ~policies ~verify (r : record) =
  match (r.details, r.sql, r.outcome) with
  | [], Some sql, (Record.Denied | Record.Shadow_denied) -> (
      match List.assoc_opt r.policy policies with
      | Some p -> Record.with_details r (verify p (Suggest.probe_context p) sql)
      | None -> r)
  | _ -> r

let report ~now ~since ~policy ~suggest ~top ~policies ~verify records =
  let records =
    List.filter
      (fun (r : record) ->
        (match r.ts with Some ts -> ts >= since | None -> true)
        && match policy with Some p -> String.equal r.policy p | None -> true)
      records
  in
  let records =
    match verify with
    | Some verify -> List.map (enrich ~policies ~verify) records
    | None -> records
  in
  (* The rolling window keeps the SQL of one record per fingerprint: share the details
     re-derived from it with the other records of the same query (only for the codes
     each record carries itself). *)
  let by_fp = Hashtbl.create 64 in
  List.iter
    (fun (r : record) ->
      if r.details <> [] && Record.fingerprint_key r <> "(none)" then
        Hashtbl.replace by_fp (r.policy, Record.fingerprint_key r) r.details)
    records;
  let records =
    List.map
      (fun (r : record) ->
        match
          (r.details, Hashtbl.find_opt by_fp (r.policy, Record.fingerprint_key r))
        with
        | [], Some ds ->
            {
              r with
              details =
                List.filter (fun (d : Record.reason) -> List.mem d.code r.codes) ds;
            }
        | _ -> r)
      records
  in
  let summary = Summary.compute ~top records in
  let suggest =
    if suggest then
      Some
        (Suggest.compute
           { Suggest.default_config with policies; pii = Pii.name_heuristic (); verify }
           records)
    else None
  in
  Render.to_json
    {
      Render.generated_at = now;
      since = Some since;
      until = Some now;
      policy_filter = policy;
      inputs = [];
      skipped_lines = 0;
      summary;
      suggest;
      notes = [];
    }
