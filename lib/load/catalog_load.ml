(* Public entry point for catalog snapshots; see catalog_load.mli. The
   implementation is Catalog_impl. *)

let of_json ?file j = Catalog_impl.of_json ?file j
let of_file = Catalog_impl.of_file
