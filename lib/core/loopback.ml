(* Loopback host test shared by every "plain text only on loopback" rule. *)

let is_ipv4_loopback h =
  match String.split_on_char '.' h with
  | [ a; b; c; d ] ->
      let octet s =
        let n = String.length s in
        n >= 1 && n <= 3
        && (not (n > 1 && s.[0] = '0'))
        && String.for_all (fun c -> c >= '0' && c <= '9') s
        && int_of_string s <= 255
      in
      a = "127" && octet b && octet c && octet d
  | _ -> false

let is_zero_group s =
  let n = String.length s in
  n >= 1 && n <= 4 && String.for_all (( = ) '0') s

let is_one_group s = s = "1" || s = "01" || s = "001" || s = "0001"

let is_ipv6_loopback h =
  let h =
    if String.length h >= 2 && h.[0] = '[' && h.[String.length h - 1] = ']' then
      String.sub h 1 (String.length h - 2)
    else h
  in
  if h = "::1" then true
  else if String.starts_with ~prefix:"::ffff:" h then
    is_ipv4_loopback (String.sub h 7 (String.length h - 7))
  else
    match String.split_on_char ':' h with
    | [ g1; g2; g3; g4; g5; g6; g7; g8 ] ->
        List.for_all is_zero_group [ g1; g2; g3; g4; g5; g6; g7 ] && is_one_group g8
    | [ g1; g2; g3; g4; g5; "ffff"; ipv4 ] ->
        List.for_all is_zero_group [ g1; g2; g3; g4; g5 ] && is_ipv4_loopback ipv4
    | _ -> false

let is_host h =
  let h = String.lowercase_ascii h in
  let h =
    if String.length h > 0 && h.[String.length h - 1] = '.' then
      String.sub h 0 (String.length h - 1)
    else h
  in
  h = "localhost" || is_ipv4_loopback h || is_ipv6_loopback h
