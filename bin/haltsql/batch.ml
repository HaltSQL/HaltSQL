(* `haltsql verify --batch`: JSONL in, JSONL out.

   Input lines:  {"id": any, "sql": string, "context": object}
   Output lines: {"id": ..., <Verdict.to_json fields>}  or  {"id": ..., "error": "..."}

   Output order always matches input order. With [jobs > 1], lines are read
   in blocks and each block is split into contiguous chunks verified on
   separate OCaml 5 domains; memory stays bounded by the block size. *)

open Haltsql

let process_line (policy : Policy.t) (default_ctx : Context.t) (line : string) : string =
  let err id msg =
    Yojson.Safe.to_string (`Assoc [ ("id", id); ("error", `String msg) ])
  in
  match Yojson.Safe.from_string line with
  | exception Yojson.Json_error e -> err `Null ("invalid JSON: " ^ e)
  | `Assoc fields -> (
      let id = Option.value (List.assoc_opt "id" fields) ~default:`Null in
      let ctx =
        match List.assoc_opt "context" fields with
        | None | Some `Null -> Ok default_ctx
        | Some j ->
            Context.of_json j |> Result.map_error (fun e -> "invalid context: " ^ e)
      in
      match (List.assoc_opt "sql" fields, ctx) with
      | (None | Some `Null), _ -> err id "missing \"sql\" (string)"
      | Some (`String _), Error e -> err id e
      | Some (`String sql), Ok ctx -> (
          match Haltsql.verify policy ctx sql with
          | v -> (
              match Verdict.to_json v with
              | `Assoc vf -> Yojson.Safe.to_string (`Assoc (("id", id) :: vf))
              | j -> Yojson.Safe.to_string (`Assoc [ ("id", id); ("verdict", j) ]))
          | exception e -> err id ("internal error: " ^ Printexc.to_string e))
      | Some _, _ -> err id "\"sql\" must be a string")
  | _ -> err `Null "each line must be a JSON object"
  | exception e -> err `Null ("internal error: " ^ Printexc.to_string e)

let is_blank s =
  String.for_all (function ' ' | '\t' | '\r' | '\n' -> true | _ -> false) s

(* Reads up to [n] non-blank lines. *)
let read_block ic n =
  let rec go acc k =
    if k = 0 then List.rev acc
    else
      match In_channel.input_line ic with
      | None -> List.rev acc
      | Some l when is_blank l -> go acc k
      | Some l -> go (l :: acc) (k - 1)
  in
  Array.of_list (go [] n)

let process_block_parallel ~jobs f (lines : string array) =
  let n = Array.length lines in
  let out = Array.make n "" in
  let jobs = max 1 (min jobs n) in
  let chunk = (n + jobs - 1) / max jobs 1 in
  let work lo hi () =
    for i = lo to hi - 1 do
      out.(i) <- f lines.(i)
    done
  in
  let domains =
    List.init (jobs - 1) (fun k ->
        let lo = (k + 1) * chunk and hi = min n ((k + 2) * chunk) in
        Domain.spawn (work lo hi))
  in
  work 0 (min n chunk) ();
  List.iter Domain.join domains;
  out

let run ~jobs (policy : Policy.t) (default_ctx : Context.t) =
  let ic = stdin and oc = stdout in
  set_binary_mode_out oc false;
  let f = process_line policy default_ctx in
  let jobs = max 1 (min jobs (Domain.recommended_domain_count () * 4)) in
  if jobs = 1 then begin
    let rec loop () =
      match In_channel.input_line ic with
      | None -> ()
      | Some l when is_blank l -> loop ()
      | Some l ->
          output_string oc (f l);
          output_char oc '\n';
          loop ()
    in
    loop ()
  end
  else begin
    let block = 4096 * jobs in
    let rec loop () =
      let lines = read_block ic block in
      if Array.length lines > 0 then begin
        let out = process_block_parallel ~jobs f lines in
        Array.iter
          (fun s ->
            output_string oc s;
            output_char oc '\n')
          out;
        loop ()
      end
    in
    loop ()
  end;
  flush oc;
  0
