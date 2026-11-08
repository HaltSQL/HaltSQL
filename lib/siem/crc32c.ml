let table =
  Array.init 256 (fun n ->
      let c = ref n in
      for _ = 0 to 7 do
        c := if !c land 1 = 1 then 0x82F63B78 lxor (!c lsr 1) else !c lsr 1
      done;
      !c)

let substring ?(crc = 0) s off len =
  if off < 0 || len < 0 || off + len > String.length s then invalid_arg "Crc32c.substring";
  let c = ref (crc lxor 0xFFFFFFFF) in
  for i = off to off + len - 1 do
    c := table.(!c lxor Char.code (String.unsafe_get s i) land 0xFF) lxor (!c lsr 8)
  done;
  !c lxor 0xFFFFFFFF

let string ?crc s = substring ?crc s 0 (String.length s)
