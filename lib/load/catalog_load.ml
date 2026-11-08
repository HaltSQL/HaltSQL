(* Public entry point for catalog snapshots; see catalog_load.mli. The
   implementation is Catalog_impl. *)

let of_json ?allow_non_authoritative ?file j =
  Catalog_impl.of_json ?allow_non_authoritative ?file j

let of_file = Catalog_impl.of_file
