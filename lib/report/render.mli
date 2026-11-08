(** A full report (summary, optional suggestions) as JSON, text or Markdown. Text and
    Markdown output strip control characters from every value taken from audit records. *)

type t = {
  generated_at : float;
  since : float option;
  until : float option;
  policy_filter : string option;
  inputs : (string * string) list;  (** (input name, status line) *)
  skipped_lines : int;  (** lines that were not audit records *)
  summary : Summary.t;
  suggest : Suggest.t option;
  notes : string list;  (** extra lines (e.g. what --apply-to did) *)
}

val to_json : t -> Yojson.Safe.t
val to_text : ?rows:int -> t -> string

val to_markdown : ?rows:int -> t -> string
(** [rows] (default 15) bounds each breakdown table. *)
