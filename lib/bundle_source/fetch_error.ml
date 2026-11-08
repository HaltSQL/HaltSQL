type t =
  | Unavailable of string
  | Denied of string
  | Not_found of string
  | Integrity of string
  | Protocol of string

let to_string = function
  | Unavailable m -> "source unavailable: " ^ m
  | Denied m -> "access denied: " ^ m
  | Not_found m -> "not found: " ^ m
  | Integrity m -> "integrity check failed: " ^ m
  | Protocol m -> "unexpected response: " ^ m

let of_status ~what status =
  let m = Printf.sprintf "%s returned HTTP %d" what status in
  if status = 401 || status = 403 then Denied m
  else if status = 404 then Not_found m
  else if status = 429 || status >= 500 then Unavailable m
  else Protocol m
