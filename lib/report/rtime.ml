(* RFC 3339 timestamps without Unix: days-from-civil arithmetic (proleptic Gregorian). *)

let days_from_civil y m d =
  let y = if m <= 2 then y - 1 else y in
  let era = (if y >= 0 then y else y - 399) / 400 in
  let yoe = y - (era * 400) in
  let mp = (m + 9) mod 12 in
  let doy = (((153 * mp) + 2) / 5) + d - 1 in
  let doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy in
  (era * 146097) + doe - 719468

let civil_from_days z =
  let z = z + 719468 in
  let era = (if z >= 0 then z else z - 146096) / 146097 in
  let doe = z - (era * 146097) in
  let yoe = (doe - (doe / 1460) + (doe / 36524) - (doe / 146096)) / 365 in
  let y = yoe + (era * 400) in
  let doy = doe - ((365 * yoe) + (yoe / 4) - (yoe / 100)) in
  let mp = ((5 * doy) + 2) / 153 in
  let d = doy - (((153 * mp) + 2) / 5) + 1 in
  let m = if mp < 10 then mp + 3 else mp - 9 in
  ((if m <= 2 then y + 1 else y), m, d)

let is_digit c = c >= '0' && c <= '9'

let digits s off len =
  if off + len > String.length s then None
  else
    let rec go i acc =
      if i = off + len then Some acc
      else if is_digit s.[i] then go (i + 1) ((acc * 10) + Char.code s.[i] - 48)
      else None
    in
    go off 0

let days_in_month y m =
  match m with
  | 2 -> if (y mod 4 = 0 && y mod 100 <> 0) || y mod 400 = 0 then 29 else 28
  | 4 | 6 | 9 | 11 -> 30
  | _ -> 31

let valid_date y m d = m >= 1 && m <= 12 && d >= 1 && d <= days_in_month y m

let parse_rfc3339 s =
  let n = String.length s in
  let ( let* ) = Option.bind in
  let* y = digits s 0 4 in
  let* m = digits s 5 2 in
  let* d = digits s 8 2 in
  let* hh = digits s 11 2 in
  let* mi = digits s 14 2 in
  let* ss = digits s 17 2 in
  if
    n < 20
    || s.[4] <> '-'
    || s.[7] <> '-'
    || (not (s.[10] = 'T' || s.[10] = 't' || s.[10] = ' '))
    || s.[13] <> ':'
    || s.[16] <> ':'
    || (not (valid_date y m d))
    || hh > 23 || mi > 59 || ss > 60
  then None
  else
    (* fraction *)
    let i = ref 19 in
    let frac =
      if !i < n && s.[!i] = '.' then begin
        incr i;
        let start = !i in
        while !i < n && is_digit s.[!i] do
          incr i
        done;
        if !i = start then None
        else Some (float_of_string ("0." ^ String.sub s start (!i - start)))
      end
      else Some 0.
    in
    let* frac = frac in
    let* offset =
      if !i >= n then None
      else
        match s.[!i] with
        | ('Z' | 'z') when !i + 1 = n -> Some 0
        | ('+' | '-') as sign when !i + 6 = n && s.[!i + 3] = ':' ->
            let* oh = digits s (!i + 1) 2 in
            let* om = digits s (!i + 4) 2 in
            if oh > 23 || om > 59 then None
            else
              let o = (oh * 3600) + (om * 60) in
              Some (if sign = '+' then o else -o)
        | _ -> None
    in
    let secs = (days_from_civil y m d * 86400) + (hh * 3600) + (mi * 60) + ss - offset in
    Some (Float.of_int secs +. frac)

let to_rfc3339 t =
  let secs = Float.to_int (Float.floor t) in
  let days = if secs >= 0 then secs / 86400 else ((secs + 1) / 86400) - 1 in
  let rem = secs - (days * 86400) in
  let y, m, d = civil_from_days days in
  Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ" y m d (rem / 3600)
    (rem mod 3600 / 60)
    (rem mod 60)

let parse_duration s =
  let n = String.length s in
  if n < 2 then
    Error (Printf.sprintf "invalid duration %S (examples: 90s, 30m, 24h, 7d)" s)
  else
    let unit_s =
      match s.[n - 1] with
      | 's' -> Some 1
      | 'm' -> Some 60
      | 'h' -> Some 3600
      | 'd' -> Some 86400
      | _ -> None
    in
    match (unit_s, digits s 0 (n - 1)) with
    | Some u, Some v when n - 1 <= 9 && v > 0 -> Ok (v * u)
    | _ -> Error (Printf.sprintf "invalid duration %S (examples: 90s, 30m, 24h, 7d)" s)

let parse_bound ~now s =
  match parse_rfc3339 s with
  | Some t -> Ok t
  | None -> (
      match
        if String.length s = 10 && s.[4] = '-' && s.[7] = '-' then
          match (digits s 0 4, digits s 5 2, digits s 8 2) with
          | Some y, Some m, Some d when valid_date y m d ->
              Some (Float.of_int (days_from_civil y m d * 86400))
          | _ -> None
        else None
      with
      | Some t -> Ok t
      | None -> (
          match parse_duration s with
          | Ok secs -> Ok (now -. Float.of_int secs)
          | Error _ ->
              Error
                (Printf.sprintf
                   "invalid time %S: expected an RFC 3339 timestamp, a date YYYY-MM-DD, \
                    or a duration such as 24h or 7d"
                   s)))
