type t = { trace_id : string; parent_id : string; flags : int }

let is_lhex c = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')

let is_hex_id ~len s =
  String.length s = len && String.for_all is_lhex s && String.exists (fun c -> c <> '0') s

let hex_val c = if c <= '9' then Char.code c - 48 else Char.code c - 87

let parse raw =
  let s = String.trim raw in
  let n = String.length s in
  if n < 55 then None
  else
    let ver = String.sub s 0 2 in
    if (not (String.for_all is_lhex ver)) || ver = "ff" then None
    else if ver = "00" && n <> 55 then None
    else if n > 55 && s.[55] <> '-' then None
    else if s.[2] <> '-' || s.[35] <> '-' || s.[52] <> '-' then None
    else
      let trace_id = String.sub s 3 32 in
      let parent_id = String.sub s 36 16 in
      let fl = String.sub s 53 2 in
      if
        is_hex_id ~len:32 trace_id && is_hex_id ~len:16 parent_id
        && String.for_all is_lhex fl
      then Some { trace_id; parent_id; flags = (hex_val fl.[0] * 16) + hex_val fl.[1] }
      else None

let to_string t = Printf.sprintf "00-%s-%s-%02x" t.trace_id t.parent_id (t.flags land 0xFF)
let sampled t = t.flags land 1 = 1
