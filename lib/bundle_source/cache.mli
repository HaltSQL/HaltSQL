(** On-disk cache of the last verified bundle of a source, so a restart can start from it
    while the source is unreachable.

    Layout, in [<cache_dir>/source-<first 16 hex of sha256(source id)>/] (mode 0700):
    - [<sha256 hex of the bundle>.haltsqlbundle] and [<same>.haltsqlbundle.sig];
    - [state.json]:
      [{"format":1,"source":...,"bundle":"<hex>.haltsqlbundle","revision":...}].

    Every file is written to a temporary file, fsynced and renamed into place; the bundle
    and signature are written before [state.json], which is the commit point, and older
    bundle files are removed afterwards. A crash at any point leaves either the previous
    or the new entry. The cache is not trusted: whatever {!load} returns must be verified
    again (signature and all) before use. *)

type entry = {
  source : string;  (** the source id the entry belongs to *)
  bundle : string;
  signature : string;
  revision : string option;  (** manifest digest or ETag of the cached bundle *)
}

val dir_for : cache_dir:string -> source:string -> string

val load : dir:string -> source:string -> (entry option, string) result
(** [Ok None] when there is no cache entry (or it belongs to another source). *)

val store : dir:string -> entry -> (unit, string) result
(** Creates [dir] (and parents) when needed. *)

val write_atomic : ?perm:int -> string -> string -> (unit, string) result
(** [write_atomic path contents]: temporary file in the same directory, fsync, rename,
    fsync of the directory (best effort). *)
