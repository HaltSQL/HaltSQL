(** Small pure helpers shared by the analyzer modules. *)

let sort_uniq_strings l = List.sort_uniq String.compare l

(** Remove structurally identical elements, keeping the first occurrence and the original
    order. *)
let dedupe l =
  let rec go seen acc = function
    | [] -> List.rev acc
    | x :: xs -> if List.mem x seen then go seen acc xs else go (x :: seen) (x :: acc) xs
  in
  go [] [] l

let rec last = function [] -> None | [ x ] -> Some x | _ :: xs -> last xs

let rec drop n l =
  if n <= 0 then l else match l with [] -> [] | _ :: xs -> drop (n - 1) xs

let index_of x l =
  let rec go i = function
    | [] -> None
    | y :: ys -> if String.equal x y then Some i else go (i + 1) ys
  in
  go 0 l

let is_int_literal s =
  let n = String.length s in
  let start = if n > 0 && (s.[0] = '+' || s.[0] = '-') then 1 else 0 in
  n > start
  &&
  let ok = ref true in
  for i = start to n - 1 do
    if s.[i] < '0' || s.[i] > '9' then ok := false
  done;
  !ok

(** Canonical decimal text of an integer literal: no ['+'], no leading zeros, ["-0"] ->
    ["0"]. Non-integers are returned unchanged. *)
let normalize_int s =
  if not (is_int_literal s) then s
  else
    let neg = s.[0] = '-' in
    let digits =
      if s.[0] = '+' || s.[0] = '-' then String.sub s 1 (String.length s - 1) else s
    in
    let n = String.length digits in
    let i = ref 0 in
    while !i < n - 1 && digits.[!i] = '0' do
      incr i
    done;
    let d = String.sub digits !i (n - !i) in
    if String.equal d "0" then "0" else if neg then "-" ^ d else d

(** Case-insensitive substring test. *)
let contains_ci ~sub s =
  let s = String.uppercase_ascii s and sub = String.uppercase_ascii sub in
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.equal (String.sub s i m) sub || go (i + 1)) in
  m = 0 || go 0

let opt_list = function None -> [] | Some x -> [ x ]
let unsupported_prefix = "Unsupported:"

let is_unsupported_kind k =
  let n = String.length unsupported_prefix in
  String.length k >= n && String.equal (String.sub k 0 n) unsupported_prefix

let unsupported_what k =
  let n = String.length unsupported_prefix in
  if is_unsupported_kind k then String.trim (String.sub k n (String.length k - n)) else k
