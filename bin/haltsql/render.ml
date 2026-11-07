(* Human-readable rendering of verdicts for `verify` and `explain`. *)

open Haltsql

let pr = Printf.printf

let print_reason ?(indent = "  ") (r : Reason.t) =
  pr "%s%s: %s%s\n" indent
    (Reason.code_to_string r.code)
    r.message
    (match r.loc with Some l -> Printf.sprintf " (at byte %d)" l | None -> "");
  match r.hint with Some h -> pr "%s  hint: %s\n" indent h | None -> ()

let print_bind_params (v : Verdict.t) =
  if v.bind_params <> [] then begin
    pr "bind parameters (the caller MUST bind these values):\n";
    List.iter
      (fun (n, value) -> pr "  $%d = %s\n" n (Common.value_to_string value))
      v.bind_params
  end

(* Output of `haltsql verify` without --json. *)
let verdict (v : Verdict.t) =
  if v.allowed then begin
    if v.shadow_reasons <> [] then begin
      pr "ALLOWED (shadow mode: would be DENIED under enforcement)\n";
      List.iter print_reason v.shadow_reasons
    end
    else pr "ALLOWED\n";
    print_bind_params v
  end
  else begin
    pr "DENIED\n";
    List.iter print_reason v.reasons
  end

(* --- caret rendering ---------------------------------------------------- *)

(* Number of UTF-8 code points in [s] between [i] and [j) (display columns,
   ignoring wide characters). Tabs are kept so the caret lines up. *)
let display_prefix s i j =
  let b = Buffer.create (j - i) in
  for k = i to j - 1 do
    let c = s.[k] in
    if c = '\t' then Buffer.add_char b '\t'
    else if Char.code c land 0xC0 <> 0x80 then Buffer.add_char b ' '
  done;
  Buffer.contents b

(* Returns [(line_number, line_text, caret_line)] for a byte offset. *)
let caret sql loc =
  let n = String.length sql in
  if loc < 0 || loc > n then None
  else
    let start =
      if loc = 0 then 0
      else
        match String.rindex_from_opt sql (loc - 1) '\n' with Some i -> i + 1 | None -> 0
    in
    let stop =
      if loc >= n then n
      else match String.index_from_opt sql loc '\n' with Some i -> i | None -> n
    in
    let line_no =
      let c = ref 1 in
      for k = 0 to start - 1 do
        if sql.[k] = '\n' then incr c
      done;
      !c
    in
    Some (line_no, String.sub sql start (stop - start), display_prefix sql start loc ^ "^")

let print_with_caret sql loc =
  match caret sql loc with
  | None -> ()
  | Some (line_no, text, caret_line) ->
      let gutter = Printf.sprintf "%4d | " line_no in
      pr "     %s%s\n" gutter text;
      pr "     %s%s\n" (String.make (String.length gutter - 2) ' ' ^ "| ") caret_line

let list_or_none = function [] -> "(none)" | l -> String.concat ", " l

(* Output of `haltsql explain`. *)
let explain (policy : Policy.t) (v : Verdict.t) sql =
  let status =
    if not v.allowed then "DENIED"
    else if v.shadow_reasons <> [] then "ALLOWED (shadow mode: would be DENIED)"
    else "ALLOWED"
  in
  pr "Verdict:      %s\n" status;
  pr "Policy:       %s (%s, mode %s)\n" v.policy_name v.policy_version
    (Common.mode_to_string policy.mode);
  pr "Statement:    %s\n" (Option.value v.statement_kind ~default:"(unknown)");
  pr "Tables:       %s\n" (list_or_none v.tables);
  pr "Columns:      %s\n" (list_or_none v.columns);
  pr "Fingerprint:  %s\n" (Option.value v.fingerprint ~default:"(none)");
  pr "SQL sha256:   %s\n" v.sql_sha256;
  pr "Elapsed:      %d us\n" v.elapsed_us;
  if v.bind_params <> [] then begin
    pr "Bind params:\n";
    List.iter
      (fun (n, value) -> pr "  $%d = %s\n" n (Common.value_to_string value))
      v.bind_params
  end;
  pr "\nSQL:\n";
  String.split_on_char '\n' sql
  |> List.iteri (fun i line -> pr "  %4d | %s\n" (i + 1) line);
  let section title (rs : Reason.t list) =
    if rs <> [] then begin
      pr "\n%s (%d):\n" title (List.length rs);
      List.iteri
        (fun i (r : Reason.t) ->
          pr "  %d. %s  [rule: %s]\n" (i + 1) (Reason.code_to_string r.code) r.rule;
          pr "     %s\n" r.message;
          (match r.hint with Some h -> pr "     hint: %s\n" h | None -> ());
          match r.loc with
          | Some l ->
              pr "     at byte %d:\n" l;
              print_with_caret sql l
          | None -> ())
        rs
    end
  in
  section "Reasons" v.reasons;
  section "Shadow reasons (not enforced)" v.shadow_reasons;
  if v.reasons = [] && v.shadow_reasons = [] then pr "\nNo policy violations.\n"
