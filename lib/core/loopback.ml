(* Loopback host test shared by every "plain text only on loopback" rule. *)

let is_ipv4_loopback h =
  match String.split_on_char '.' h with
  | [ a; b; c; d ] ->
      let octet s =
        let n = String.length s in
        n >= 1 && n <= 3
        && String.for_all (fun c -> c >= '0' && c <= '9') s
        && int_of_string s <= 255
      in
      a = "127" && octet b && octet c && octet d
  | _ -> false

let is_host h =
  let h = String.lowercase_ascii h in
  h = "localhost" || h = "::1" || h = "[::1]" || is_ipv4_loopback h
