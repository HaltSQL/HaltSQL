(* gzip = header + DEFLATE + CRC-32/ISIZE trailer. The compressor uses only
   fixed-Huffman blocks (one block for the whole input) with a hash-chain LZ77
   matcher; the inflater follows the structure of zlib's "puff". *)

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

let len_base =
  [|
    3;
    4;
    5;
    6;
    7;
    8;
    9;
    10;
    11;
    13;
    15;
    17;
    19;
    23;
    27;
    31;
    35;
    43;
    51;
    59;
    67;
    83;
    99;
    115;
    131;
    163;
    195;
    227;
    258;
  |]

let len_extra =
  [|
    0; 0; 0; 0; 0; 0; 0; 0; 1; 1; 1; 1; 2; 2; 2; 2; 3; 3; 3; 3; 4; 4; 4; 4; 5; 5; 5; 5; 0;
  |]

let dist_base =
  [|
    1;
    2;
    3;
    4;
    5;
    7;
    9;
    13;
    17;
    25;
    33;
    49;
    65;
    97;
    129;
    193;
    257;
    385;
    513;
    769;
    1025;
    1537;
    2049;
    3073;
    4097;
    6145;
    8193;
    12289;
    16385;
    24577;
  |]

let dist_extra =
  [|
    0;
    0;
    0;
    0;
    1;
    1;
    2;
    2;
    3;
    3;
    4;
    4;
    5;
    5;
    6;
    6;
    7;
    7;
    8;
    8;
    9;
    9;
    10;
    10;
    11;
    11;
    12;
    12;
    13;
    13;
  |]

(* ---- compression ---- *)

type bw = { out : Buffer.t; mutable bitbuf : int; mutable bitcnt : int }

let put_bits w v n =
  w.bitbuf <- w.bitbuf lor (v lsl w.bitcnt);
  w.bitcnt <- w.bitcnt + n;
  while w.bitcnt >= 8 do
    Buffer.add_char w.out (Char.chr (w.bitbuf land 0xFF));
    w.bitbuf <- w.bitbuf lsr 8;
    w.bitcnt <- w.bitcnt - 8
  done

let reverse v n =
  let r = ref 0 in
  for i = 0 to n - 1 do
    if v land (1 lsl i) <> 0 then r := !r lor (1 lsl (n - 1 - i))
  done;
  !r

(* Huffman codes are packed MSB-first. *)
let put_code w code n = put_bits w (reverse code n) n

let put_lit w v =
  if v < 144 then put_code w (0x30 + v) 8
  else if v < 256 then put_code w (0x190 + v - 144) 9
  else if v < 280 then put_code w (v - 256) 7
  else put_code w (0xC0 + v - 280) 8

let find_index base v =
  let i = ref (Array.length base - 1) in
  while base.(!i) > v do
    decr i
  done;
  !i

let put_match w len dist =
  let li = find_index len_base len in
  put_lit w (257 + li);
  if len_extra.(li) > 0 then put_bits w (len - len_base.(li)) len_extra.(li);
  let di = find_index dist_base dist in
  put_code w di 5;
  if dist_extra.(di) > 0 then put_bits w (dist - dist_base.(di)) dist_extra.(di)

let hash_bits = 15
let window = 32768
let max_chain = 64

let deflate s =
  let n = String.length s in
  let w = { out = Buffer.create ((n / 2) + 16); bitbuf = 0; bitcnt = 0 } in
  put_bits w 1 1 (* BFINAL *);
  put_bits w 1 2 (* BTYPE = 01, fixed Huffman *);
  let head = Array.make (1 lsl hash_bits) (-1) in
  let prev = Array.make (max n 1) (-1) in
  let hash i =
    (Char.code s.[i] lsl 10)
    lxor (Char.code s.[i + 1] lsl 5)
    lxor Char.code s.[i + 2]
    land ((1 lsl hash_bits) - 1)
  in
  let insert i =
    if i + 2 < n then begin
      let h = hash i in
      prev.(i) <- head.(h);
      head.(h) <- i
    end
  in
  let i = ref 0 in
  while !i < n do
    let best_len = ref 0 and best_dist = ref 0 in
    if !i + 2 < n then begin
      let cand = ref head.(hash !i) in
      let chain = ref 0 in
      let maxlen = min 258 (n - !i) in
      while !cand >= 0 && !i - !cand <= window && !chain < max_chain do
        let c = !cand in
        let l = ref 0 in
        while !l < maxlen && s.[c + !l] = s.[!i + !l] do
          incr l
        done;
        if !l > !best_len then begin
          best_len := !l;
          best_dist := !i - c
        end;
        cand := prev.(c);
        incr chain
      done
    end;
    if !best_len >= 3 then begin
      put_match w !best_len !best_dist;
      for k = !i to !i + !best_len - 1 do
        insert k
      done;
      i := !i + !best_len
    end
    else begin
      put_lit w (Char.code s.[!i]);
      insert !i;
      incr i
    end
  done;
  put_lit w 256;
  if w.bitcnt > 0 then put_bits w 0 (8 - w.bitcnt);
  Buffer.contents w.out

let le32 b v =
  for k = 0 to 3 do
    Buffer.add_char b
      (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical v (8 * k)) 0xFFl)))
  done

let compress s =
  let b = Buffer.create ((String.length s / 2) + 32) in
  Buffer.add_string b "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff";
  Buffer.add_string b (deflate s);
  le32 b (crc32 s);
  le32 b (Int32.of_int (String.length s land 0xFFFFFFFF));
  Buffer.contents b

(* ---- decompression ---- *)

exception Bad of string

type br = { src : string; mutable pos : int; mutable bb : int; mutable bc : int }

let bits r n =
  while r.bc < n do
    if r.pos >= String.length r.src then raise (Bad "unexpected end of deflate stream");
    r.bb <- r.bb lor (Char.code r.src.[r.pos] lsl r.bc);
    r.pos <- r.pos + 1;
    r.bc <- r.bc + 8
  done;
  let v = r.bb land ((1 lsl n) - 1) in
  r.bb <- r.bb lsr n;
  r.bc <- r.bc - n;
  v

type huff = { count : int array; symbol : int array }

let build lengths nsym =
  let count = Array.make 16 0 in
  for i = 0 to nsym - 1 do
    count.(lengths.(i)) <- count.(lengths.(i)) + 1
  done;
  let left = ref 1 in
  for len = 1 to 15 do
    left := (!left lsl 1) - count.(len);
    if !left < 0 then raise (Bad "over-subscribed Huffman code")
  done;
  let offs = Array.make 16 0 in
  for len = 1 to 14 do
    offs.(len + 1) <- offs.(len) + count.(len)
  done;
  let symbol = Array.make nsym 0 in
  for i = 0 to nsym - 1 do
    if lengths.(i) <> 0 then begin
      symbol.(offs.(lengths.(i))) <- i;
      offs.(lengths.(i)) <- offs.(lengths.(i)) + 1
    end
  done;
  { count; symbol }

let decode r h =
  let code = ref 0 and first = ref 0 and index = ref 0 in
  let result = ref (-1) in
  let len = ref 1 in
  while !result < 0 do
    if !len > 15 then raise (Bad "invalid Huffman code");
    code := !code lor bits r 1;
    let c = h.count.(!len) in
    if !code - c < !first then result := h.symbol.(!index + (!code - !first))
    else begin
      index := !index + c;
      first := (!first + c) lsl 1;
      code := !code lsl 1;
      incr len
    end
  done;
  !result

let fixed_tables =
  lazy
    (let l = Array.make 288 0 in
     for i = 0 to 287 do
       l.(i) <- (if i < 144 then 8 else if i < 256 then 9 else if i < 280 then 7 else 8)
     done;
     (build l 288, build (Array.make 30 5) 30))

let inflate ~max_size src start =
  let r = { src; pos = start; bb = 0; bc = 0 } in
  let out = Buffer.create 4096 in
  let add c =
    if Buffer.length out >= max_size then raise (Bad "decompressed size limit exceeded");
    Buffer.add_char out c
  in
  let codes lencode distcode =
    let fin = ref false in
    while not !fin do
      let sym = decode r lencode in
      if sym < 256 then add (Char.chr sym)
      else if sym = 256 then fin := true
      else begin
        let sym = sym - 257 in
        if sym >= 29 then raise (Bad "invalid length symbol");
        let len = len_base.(sym) + bits r len_extra.(sym) in
        let ds = decode r distcode in
        if ds >= 30 then raise (Bad "invalid distance symbol");
        let dist = dist_base.(ds) + bits r dist_extra.(ds) in
        if dist > Buffer.length out then raise (Bad "distance too far back");
        for _ = 1 to len do
          add (Buffer.nth out (Buffer.length out - dist))
        done
      end
    done
  in
  let last = ref false in
  while not !last do
    last := bits r 1 = 1;
    match bits r 2 with
    | 0 ->
        r.bb <- 0;
        r.bc <- 0;
        if r.pos + 4 > String.length src then raise (Bad "truncated stored block");
        let len = Char.code src.[r.pos] lor (Char.code src.[r.pos + 1] lsl 8) in
        let nlen = Char.code src.[r.pos + 2] lor (Char.code src.[r.pos + 3] lsl 8) in
        if len <> lnot nlen land 0xFFFF then raise (Bad "stored block length mismatch");
        r.pos <- r.pos + 4;
        if r.pos + len > String.length src then raise (Bad "truncated stored block");
        for k = 0 to len - 1 do
          add src.[r.pos + k]
        done;
        r.pos <- r.pos + len
    | 1 ->
        let l, d = Lazy.force fixed_tables in
        codes l d
    | 2 ->
        let nlen = bits r 5 + 257 in
        let ndist = bits r 5 + 1 in
        let ncode = bits r 4 + 4 in
        if nlen > 286 || ndist > 30 then raise (Bad "bad dynamic block counts");
        let order =
          [| 16; 17; 18; 0; 8; 7; 9; 6; 10; 5; 11; 4; 12; 3; 13; 2; 14; 1; 15 |]
        in
        let lengths = Array.make 320 0 in
        for k = 0 to ncode - 1 do
          lengths.(order.(k)) <- bits r 3
        done;
        let lencode = build lengths 19 in
        let lengths = Array.make 320 0 in
        let idx = ref 0 in
        while !idx < nlen + ndist do
          let sym = decode r lencode in
          if sym < 16 then begin
            lengths.(!idx) <- sym;
            incr idx
          end
          else begin
            let v, rep =
              match sym with
              | 16 ->
                  if !idx = 0 then raise (Bad "repeat with no previous length");
                  (lengths.(!idx - 1), 3 + bits r 2)
              | 17 -> (0, 3 + bits r 3)
              | _ -> (0, 11 + bits r 7)
            in
            if !idx + rep > nlen + ndist then raise (Bad "too many lengths");
            for _ = 1 to rep do
              lengths.(!idx) <- v;
              incr idx
            done
          end
        done;
        let lencode = build (Array.sub lengths 0 nlen) nlen in
        let distcode = build (Array.sub lengths nlen ndist) ndist in
        codes lencode distcode
    | _ -> raise (Bad "invalid block type")
  done;
  (Buffer.contents out, r.pos)

let rd32 s p =
  let b k = Int32.of_int (Char.code s.[p + k]) in
  Int32.(
    logor (b 0)
      (logor (shift_left (b 1) 8) (logor (shift_left (b 2) 16) (shift_left (b 3) 24))))

let decompress ?(max_size = 64 * 1024 * 1024) s =
  try
    let n = String.length s in
    if n < 18 || s.[0] <> '\x1f' || s.[1] <> '\x8b' || s.[2] <> '\x08' then
      raise (Bad "not a gzip stream");
    let flg = Char.code s.[3] in
    let p = ref 10 in
    if flg land 4 <> 0 then begin
      if !p + 2 > n then raise (Bad "truncated header");
      let xlen = Char.code s.[!p] lor (Char.code s.[!p + 1] lsl 8) in
      p := !p + 2 + xlen
    end;
    let skip_z () =
      while !p < n && s.[!p] <> '\x00' do
        incr p
      done;
      incr p
    in
    if flg land 8 <> 0 then skip_z ();
    if flg land 16 <> 0 then skip_z ();
    if flg land 2 <> 0 then p := !p + 2;
    if !p >= n then raise (Bad "truncated header");
    let data, endp = inflate ~max_size s !p in
    if endp + 8 > n then raise (Bad "truncated trailer");
    if rd32 s endp <> crc32 data then raise (Bad "CRC-32 mismatch");
    if rd32 s (endp + 4) <> Int32.of_int (String.length data land 0xFFFFFFFF) then
      raise (Bad "size mismatch");
    Ok data
  with
  | Bad m -> Error m
  | Invalid_argument _ -> Error "corrupt gzip stream"
