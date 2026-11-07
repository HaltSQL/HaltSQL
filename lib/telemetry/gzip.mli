(** Minimal, dependency-free gzip (RFC 1952) over DEFLATE (RFC 1951).

    [compress] emits fixed-Huffman blocks with LZ77 matching (good ratios on the
    repetitive OTLP JSON payloads); [decompress] is a complete inflater (stored, fixed and
    dynamic blocks) used by tests and fake collectors. *)

val crc32 : string -> int32
(** IEEE CRC-32 (the gzip trailer checksum). *)

val compress : string -> string
(** A complete gzip member (header, deflate stream, CRC-32 and size trailer). *)

val decompress : ?max_size:int -> string -> (string, string) result
(** Inflates one gzip member, checking the CRC-32 and size trailer. Fails when the output
    would exceed [max_size] bytes (default 64 MiB). *)
