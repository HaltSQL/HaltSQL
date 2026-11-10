(* Minimal archive writers for evidence packs: POSIX ustar and gzip.

   No tar or compression library is a dependency of haltsql-server, so this writes the
   two formats directly. The gzip stream uses DEFLATE "stored" blocks (RFC 1951 BTYPE=00):
   a valid gzip file that every gunzip and [tar -xzf] reads, without compression. Audit
   records are what make a pack large, and they are kept verbatim on purpose. *)

(* ---- CRC-32 (IEEE 802.3, as gzip uses) ----

   On native ints (63-bit), so no boxed Int32 per byte. *)

let crc_table =
  lazy
    (Array.init 256 (fun n ->
         let c = ref n in
         for _ = 0 to 7 do
           if !c land 1 <> 0 then c := 0xEDB88320 lxor (!c lsr 1) else c := !c lsr 1
         done;
         !c))

(** [crc32_update crc s off len] continues a CRC-32 over [s.[off .. off+len-1]]; start
    with [0] (the result is the finished CRC of everything fed so far). *)
let crc32_update crc s off len =
  let t = Lazy.force crc_table in
  let c = ref (crc lxor 0xFFFFFFFF) in
  for i = off to off + len - 1 do
    c := t.(!c lxor Char.code (String.unsafe_get s i) land 0xFF) lxor (!c lsr 8)
  done;
  !c lxor 0xFFFFFFFF

let crc32 s = Int32.of_int (crc32_update 0 s 0 (String.length s))
let le32 (v : int) = String.init 4 (fun i -> Char.chr ((v lsr (8 * i)) land 0xFF))
let le16 v = String.init 2 (fun i -> Char.chr ((v lsr (8 * i)) land 0xFF))

(* ---- streaming gzip (stored DEFLATE blocks) ---- *)

type sink = string -> unit
(** Receives the archive's bytes in order. *)

let block_max = 65535

type gz = {
  out : sink;
  block : Buffer.t;  (** pending bytes of the current stored block *)
  mutable crc : int;
  mutable size : int;
}

let gz_create ?(mtime = 0.) out =
  (* ID1 ID2 CM=deflate FLG=0 MTIME XFL=0 OS=255 (unknown) *)
  out "\x1f\x8b\x08\x00";
  out (le32 (int_of_float (Float.max 0. (Float.min mtime 2147483647.))));
  out "\x00\xff";
  { out; block = Buffer.create block_max; crc = 0; size = 0 }

let gz_flush_block g ~final =
  let len = Buffer.length g.block in
  g.out (if final then "\x01" else "\x00");
  g.out (le16 len);
  g.out (le16 (lnot len land 0xFFFF));
  g.out (Buffer.contents g.block);
  Buffer.clear g.block

let gz_add_sub g s off len =
  g.crc <- crc32_update g.crc s off len;
  g.size <- g.size + len;
  let rec go off len =
    if len > 0 then (
      let room = block_max - Buffer.length g.block in
      let k = min room len in
      Buffer.add_substring g.block s off k;
      if Buffer.length g.block = block_max then gz_flush_block g ~final:false;
      go (off + k) (len - k))
  in
  go off len

let gz_add g s = gz_add_sub g s 0 (String.length s)

(* The last block is always flagged final, possibly empty (a valid stored block). *)
let gz_finish g =
  gz_flush_block g ~final:true;
  g.out (le32 g.crc);
  g.out (le32 (g.size land 0xFFFFFFFF))

(** A gzip member holding [data] in stored DEFLATE blocks. *)
let gzip ?mtime data =
  let b =
    Buffer.create (String.length data + (String.length data / block_max * 5) + 32)
  in
  let g = gz_create ?mtime (Buffer.add_string b) in
  gz_add g data;
  gz_finish g;
  Buffer.contents b

(* ---- ustar ---- *)

let octal width v =
  (* width-1 octal digits, NUL-terminated *)
  let s = Printf.sprintf "%0*o" (width - 1) v in
  if String.length s > width - 1 then invalid_arg "Pack.octal: value too large";
  s ^ "\000"

let field width s =
  if String.length s > width then invalid_arg ("Pack: field too long: " ^ s);
  s ^ String.make (width - String.length s) '\000'

(** One ustar header for a regular file. [name] must be at most 100 bytes (or split into
    prefix/name at a '/' when longer, up to 255). *)
let header ~name ~size ~mtime =
  let prefix, name =
    if String.length name <= 100 then ("", name)
    else
      match String.rindex_from_opt name (min 155 (String.length name - 1)) '/' with
      | Some i when String.length name - i - 1 <= 100 ->
          (String.sub name 0 i, String.sub name (i + 1) (String.length name - i - 1))
      | _ -> invalid_arg ("Pack: path too long: " ^ name)
  in
  let h ~chk =
    String.concat ""
      [
        field 100 name;
        octal 8 0o644;
        octal 8 0;
        octal 8 0;
        octal 12 size;
        octal 12 mtime;
        chk;
        "0";
        field 100 "";
        "ustar\00000";
        field 32 "haltsql";
        field 32 "haltsql";
        octal 8 0;
        octal 8 0;
        field 155 prefix;
        String.make 12 '\000';
      ]
  in
  let blank = h ~chk:(String.make 8 ' ') in
  assert (String.length blank = 512);
  let sum = ref 0 in
  String.iter (fun c -> sum := !sum + Char.code c) blank;
  h ~chk:(Printf.sprintf "%06o\000 " !sum)

(* ---- streaming .tar.gz ---- *)

type writer = { gz : gz; mtime : int }

(** A .tar.gz written to [out] as files are added, so a pack never has to be held in
    memory as a whole: only the file being added. *)
let create ?(mtime = 0.) out = { gz = gz_create ~mtime out; mtime = int_of_float mtime }

let add_file w ~name data =
  let size = String.length data in
  gz_add w.gz (header ~name ~size ~mtime:w.mtime);
  gz_add w.gz data;
  let pad = (512 - (size mod 512)) mod 512 in
  if pad > 0 then gz_add w.gz (String.make pad '\000')

(** Writes the end-of-archive marker and the gzip trailer. *)
let finish w =
  gz_add w.gz (String.make 1024 '\000');
  gz_finish w.gz

(** A tar archive of [(path, contents)] entries (uncompressed). *)
let tar ?(mtime = 0.) files =
  let b = Buffer.create 4096 in
  let mtime = int_of_float mtime in
  List.iter
    (fun (name, data) ->
      let size = String.length data in
      Buffer.add_string b (header ~name ~size ~mtime);
      Buffer.add_string b data;
      let pad = (512 - (size mod 512)) mod 512 in
      Buffer.add_string b (String.make pad '\000'))
    files;
  Buffer.add_string b (String.make 1024 '\000');
  Buffer.contents b

let tar_gz ?mtime files =
  let b = Buffer.create 4096 in
  let w = create ?mtime (Buffer.add_string b) in
  List.iter (fun (name, data) -> add_file w ~name data) files;
  finish w;
  Buffer.contents b
