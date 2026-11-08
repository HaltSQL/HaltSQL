(* Text / Markdown / JSON rendering of a report. *)

type t = {
  generated_at : float;
  since : float option;
  until : float option;
  policy_filter : string option;
  inputs : (string * string) list;
  skipped_lines : int;
  summary : Summary.t;
  suggest : Suggest.t option;
  notes : string list;
}

let ts_json = function Some t -> `String (Rtime.to_rfc3339 t) | None -> `Null

let to_json t : Yojson.Safe.t =
  `Assoc
    ([
       ("generated_at", `String (Rtime.to_rfc3339 t.generated_at));
       ("since", ts_json t.since);
       ("until", ts_json t.until);
       ("policy_filter", match t.policy_filter with Some p -> `String p | None -> `Null);
       ( "inputs",
         `List
           (List.map
              (fun (n, s) -> `Assoc [ ("input", `String n); ("status", `String s) ])
              t.inputs) );
       ("skipped_lines", `Int t.skipped_lines);
       ("summary", Summary.to_json t.summary);
     ]
    @ (match t.suggest with Some s -> [ ("suggest", Suggest.to_json s) ] | None -> [])
    @ [ ("notes", `List (List.map (fun n -> `String n) t.notes)) ])

(* Values from audit records may contain terminal escapes or Markdown. *)
let clean s =
  String.map (fun c -> if Char.code c < 0x20 || Char.code c = 0x7f then ' ' else c) s

let clean_ml s = String.concat "\n" (List.map clean (String.split_on_char '\n' s))

let md_cell s =
  let b = Buffer.create (String.length s) in
  String.iter
    (fun c ->
      match c with
      | '|' -> Buffer.add_string b "\\|"
      | '`' -> Buffer.add_string b "'"
      | '<' -> Buffer.add_string b "&lt;"
      | '>' -> Buffer.add_string b "&gt;"
      | c -> Buffer.add_char b c)
    (clean s);
  Buffer.contents b

let take n l = List.filteri (fun i _ -> i < n) l

let window t =
  let s = function Some x -> Rtime.to_rfc3339 x | None -> "-" in
  let lo = match t.since with Some _ -> t.since | None -> t.summary.first_ts in
  let hi = match t.until with Some _ -> t.until | None -> t.summary.last_ts in
  Printf.sprintf "%s .. %s" (s lo) (s hi)

let count_line (c : Summary.count) =
  Printf.sprintf "%d (allowed %d, denied %d, shadow-denied %d)" c.total c.allowed c.denied
    c.shadow_denied

(* A fence longer than any backtick run in [s]. *)
let fence s =
  let longest = ref 0 and cur = ref 0 in
  String.iter
    (fun c ->
      if c = '`' then begin
        incr cur;
        if !cur > !longest then longest := !cur
      end
      else cur := 0)
    s;
  String.make (max 3 (!longest + 1)) '`'

let to_text ?(rows = 15) t =
  let b = Buffer.create 4096 in
  let p fmt = Printf.bprintf b fmt in
  let s = t.summary in
  p "HaltSQL shadow report\n";
  p "  records:  %s\n" (count_line s.totals);
  p "  window:   %s\n" (window t);
  (match t.policy_filter with Some f -> p "  policy:   %s\n" (clean f) | None -> ());
  List.iter (fun (n, st) -> p "  input:    %s: %s\n" (clean n) (clean st)) t.inputs;
  if t.skipped_lines > 0 then
    p "  skipped:  %d line(s) that are not audit records\n" t.skipped_lines;
  p "  detail:   %d record(s) with raw SQL, %d with detailed reasons\n" s.with_sql
    s.with_details;
  let section title (l : (string * Summary.count) list) =
    if l <> [] then begin
      p "\n%s\n" title;
      let w = List.fold_left (fun w (k, _) -> max w (String.length k)) 0 (take rows l) in
      let w = min w 60 in
      List.iter
        (fun (k, (c : Summary.count)) ->
          p "  %-*s %6d   denied %d, shadow-denied %d\n" w (clean k) c.total c.denied
            c.shadow_denied)
        (take rows l);
      if List.length l > rows then p "  ... %d more\n" (List.length l - rows)
    end
  in
  section "By reason code" s.by_code;
  section "By table" s.by_table;
  section "By column" s.by_column;
  section "By caller" s.by_caller;
  section "By policy" s.by_policy;
  if s.buckets <> [] then begin
    p "\nOver time (bucket %ds)\n" s.bucket_seconds;
    let maxt =
      List.fold_left (fun m (_, (c : Summary.count)) -> max m c.total) 1 s.buckets
    in
    List.iter
      (fun (start, (c : Summary.count)) ->
        p "  %s %6d  denied %d, shadow-denied %d  %s\n" (Rtime.to_rfc3339 start) c.total
          c.denied c.shadow_denied
          (String.make (max 1 (c.total * 30 / maxt)) '#'))
      s.buckets
  end;
  if s.top_denied <> [] then begin
    p "\nTop denied queries\n";
    List.iteri
      (fun i (q : Summary.query) ->
        p "  %d. %s  x%d (denied %d, shadow-denied %d)\n" (i + 1) (clean q.key)
          q.count.total q.count.denied q.count.shadow_denied;
        p "     codes: %s\n"
          (String.concat ", "
             (List.map (fun (c, n) -> Printf.sprintf "%s x%d" (clean c) n) q.codes));
        p "     callers: %s\n"
          (String.concat ", "
             (List.map
                (fun (c, n) -> Printf.sprintf "%s x%d" (clean c) n)
                (take 5 q.callers)));
        match q.example_sql with
        | Some sql -> p "     example: %s\n" (clean sql)
        | None -> ())
      s.top_denied
  end;
  (match t.suggest with
  | None -> ()
  | Some g ->
      p "\nSuggestions (%d)\n" (List.length g.suggestions);
      if g.suggestions = [] then p "  none\n";
      List.iter
        (fun (x : Suggest.suggestion) ->
          p "  [%s]%s\n    %s\n" (clean x.id)
            (if x.applicable then "" else " (not applicable automatically)")
            (clean x.summary);
          List.iter
            (fun l -> if l <> "" then p "      %s\n" (clean l))
            (String.split_on_char '\n' x.yaml);
          List.iter (fun n -> p "    note: %s\n" (clean n)) x.notes)
        g.suggestions;
      if g.pii_flagged <> [] then begin
        p "\nSensitive columns (flagged, never suggested)\n";
        List.iter
          (fun (i : Suggest.item) ->
            p "  %s/%s  x%d: %s\n" (clean i.i_policy) (clean i.target)
              i.i_evidence.records (clean i.reason))
          g.pii_flagged
      end;
      if g.not_suggested <> [] then begin
        p "\nNot suggested\n";
        List.iter
          (fun (i : Suggest.item) ->
            p "  %s/%s  %s x%d [%s]: %s\n" (clean i.i_policy) (clean i.target)
              (clean i.i_code) i.i_evidence.records
              (Suggest.category_to_string i.category)
              (clean i.reason))
          g.not_suggested
      end;
      if g.codes <> [] then begin
        p "\nNeeds a query fix, not a policy change (or never relaxed)\n";
        List.iter
          (fun (r : Suggest.code_row) ->
            p "  %-22s %6d  [%s] %s\n" (clean r.c_code) r.c_records
              (Suggest.category_to_string r.c_category)
              r.advice)
          g.codes
      end;
      if g.missing_detail > 0 then
        p
          "\n\
           %d denied record(s) have a policy-fixable code but no detail: enable raw SQL \
           in the audit log (audit.log_raw_sql) and pass --policy-file, or use the \
           server's /v1/admin/report.\n"
          g.missing_detail);
  if t.notes <> [] then begin
    p "\n";
    List.iter (fun n -> p "%s\n" (clean n)) t.notes
  end;
  Buffer.contents b

let to_markdown ?(rows = 15) t =
  let b = Buffer.create 4096 in
  let p fmt = Printf.bprintf b fmt in
  let s = t.summary in
  p "# HaltSQL shadow report\n\n";
  p "- **Records:** %s\n" (count_line s.totals);
  p "- **Window:** %s\n" (window t);
  (match t.policy_filter with Some f -> p "- **Policy:** %s\n" (md_cell f) | None -> ());
  List.iter (fun (n, st) -> p "- **Input:** `%s`: %s\n" (md_cell n) (md_cell st)) t.inputs;
  if t.skipped_lines > 0 then
    p "- **Skipped:** %d line(s) that are not audit records\n" t.skipped_lines;
  p "- **Detail:** %d record(s) with raw SQL, %d with detailed reasons\n" s.with_sql
    s.with_details;
  let table title key (l : (string * Summary.count) list) =
    if l <> [] then begin
      p "\n## %s\n\n| %s | Total | Denied | Shadow-denied |\n|---|---:|---:|---:|\n" title
        key;
      List.iter
        (fun (k, (c : Summary.count)) ->
          p "| %s | %d | %d | %d |\n" (md_cell k) c.total c.denied c.shadow_denied)
        (take rows l);
      if List.length l > rows then p "\n%d more not shown.\n" (List.length l - rows)
    end
  in
  table "By reason code" "Code" s.by_code;
  table "By table" "Table" s.by_table;
  table "By column" "Column" s.by_column;
  table "By caller" "Caller" s.by_caller;
  table "By policy" "Policy" s.by_policy;
  if s.buckets <> [] then begin
    p
      "\n\
       ## Over time (bucket %ds)\n\n\
       | Start | Total | Denied | Shadow-denied |\n\
       |---|---:|---:|---:|\n"
      s.bucket_seconds;
    List.iter
      (fun (start, (c : Summary.count)) ->
        p "| %s | %d | %d | %d |\n" (Rtime.to_rfc3339 start) c.total c.denied
          c.shadow_denied)
      s.buckets
  end;
  if s.top_denied <> [] then begin
    p "\n## Top denied queries\n";
    List.iteri
      (fun i (q : Summary.query) ->
        p "\n%d. `%s`: %d (denied %d, shadow-denied %d); codes %s; callers %s\n" (i + 1)
          (md_cell q.key) q.count.total q.count.denied q.count.shadow_denied
          (String.concat ", "
             (List.map (fun (c, n) -> Printf.sprintf "%s x%d" (md_cell c) n) q.codes))
          (String.concat ", "
             (List.map
                (fun (c, n) -> Printf.sprintf "%s x%d" (md_cell c) n)
                (take 5 q.callers)));
        match q.example_sql with
        | Some sql ->
            let sql = clean_ml sql in
            let f = fence sql in
            p "\n   %ssql\n   %s\n   %s\n" f sql f
        | None -> ())
      s.top_denied
  end;
  (match t.suggest with
  | None -> ()
  | Some g ->
      p "\n## Suggestions\n";
      if g.suggestions = [] then p "\nNone.\n";
      List.iter
        (fun (x : Suggest.suggestion) ->
          p "\n### `%s`%s\n\n%s\n\n" (md_cell x.id)
            (if x.applicable then "" else " (not applicable automatically)")
            (md_cell x.summary);
          let y = clean_ml x.yaml in
          let f = fence y in
          p "%syaml\n%s%s\n" f y f;
          List.iter (fun n -> p "\n> %s\n" (md_cell n)) x.notes)
        g.suggestions;
      let items title (l : Suggest.item list) =
        if l <> [] then begin
          p
            "\n\
             ## %s\n\n\
             | Policy | Target | Code | Records | Category | Why |\n\
             |---|---|---|---:|---|---|\n"
            title;
          List.iter
            (fun (i : Suggest.item) ->
              p "| %s | %s | %s | %d | %s | %s |\n" (md_cell i.i_policy)
                (md_cell i.target) (md_cell i.i_code) i.i_evidence.records
                (Suggest.category_to_string i.category)
                (md_cell i.reason))
            l
        end
      in
      items "Sensitive columns (flagged, never suggested)" g.pii_flagged;
      items "Not suggested" g.not_suggested;
      if g.codes <> [] then begin
        p
          "\n\
           ## Needs a query fix, not a policy change\n\n\
           | Code | Records | Category | Advice |\n\
           |---|---:|---|---|\n";
        List.iter
          (fun (r : Suggest.code_row) ->
            p "| %s | %d | %s | %s |\n" (md_cell r.c_code) r.c_records
              (Suggest.category_to_string r.c_category)
              (md_cell r.advice))
          g.codes
      end;
      if g.missing_detail > 0 then
        p
          "\n\
           %d denied record(s) have a policy-fixable code but no detail: enable \
           `audit.log_raw_sql` and pass `--policy-file`, or use `/v1/admin/report`.\n"
          g.missing_detail);
  if t.notes <> [] then begin
    p "\n";
    List.iter (fun n -> p "- %s\n" (md_cell n)) t.notes
  end;
  Buffer.contents b
