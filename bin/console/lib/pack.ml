(* Minimal archive writers for evidence packs: POSIX ustar and gzip.

   No tar or compression library is a dependency of haltsql-server, so this writes the
   two formats directly. The gzip stream uses DEFLATE "stored" blocks (RFC 1951 BTYPE=00):
   a valid gzip file that every gunzip and [tar -xzf] reads, without compression. Audit
   records are what make a pack large, and they are kept verbatim on purpose. *)

(* ---- CRC-32 (IEEE 802.3, as gzip uses) ---- *)

let crc_table =
  lazy
    (Array.init 256 (fun n ->
         let c = ref (Int32.of_int n) in
         for _ = 0 to 7 do
           if Int32.logand !c 1l <> 0l then
             c := Int32.logxor 0xEDB88320l (Int32.shift_right_logical !c 1)
           else c := Int32.shift_right_logical !c 1
         done;
         !c))

let crc32 s =
  let t = Lazy.force crc_table in
  let c = ref 0xFFFFFFFFl in
  String.iter
    (fun ch ->
      let idx =
        Int32.to_int (Int32.logand (Int32.logxor !c (Int32.of_int (Char.code ch))) 0xFFl)
      in
      c := Int32.logxor t.(idx) (Int32.shift_right_logical !c 8))
    s;
  Int32.logxor !c 0xFFFFFFFFl

let add_le32 b (v : int32) =
  for i = 0 to 3 do
    Buffer.add_char b
      (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical v (8 * i)) 0xFFl)))
  done

let add_le16 b v =
  Buffer.add_char b (Char.chr (v land 0xFF));
  Buffer.add_char b (Char.chr ((v lsr 8) land 0xFF))

(** A gzip member holding [data] in stored DEFLATE blocks. *)
let gzip ?(mtime = 0.) data =
  let n = String.length data in
  let b = Buffer.create (n + (n / 65535 * 5) + 32) in
  (* ID1 ID2 CM=deflate FLG=0 MTIME XFL=0 OS=255 (unknown) *)
  Buffer.add_string b "\x1f\x8b\x08\x00";
  add_le32 b (Int32.of_float (Float.min mtime 2147483647.));
  Buffer.add_string b "\x00\xff";
  let rec blocks off =
    let len = min 65535 (n - off) in
    let final = off + len >= n in
    Buffer.add_char b (if final then '\x01' else '\x00');
    add_le16 b len;
    add_le16 b (lnot len land 0xFFFF);
    Buffer.add_substring b data off len;
    if not final then blocks (off + len)
  in
  blocks 0;
  add_le32 b (crc32 data);
  add_le32 b (Int32.of_int (n land 0xFFFFFFFF));
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

(** A tar archive of [(path, contents)] entries. *)
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

let tar_gz ?mtime files = gzip ?mtime (tar ?mtime files)
