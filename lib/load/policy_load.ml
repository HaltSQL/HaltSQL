(* Public entry point for policy documents; see policy_load.mli. The
   implementation is Policy_impl. *)

let of_json ?file ?base_dir j = Policy_impl.of_json ?file ?base_dir j
let of_file = Policy_impl.of_file

let of_string ?file ?base_dir (fmt : Docload.format) s =
  Policy_impl.of_string ?file ?base_dir
    (match fmt with Docload.Yaml -> Docpos.Yaml | Json -> Docpos.Json)
    s

let to_json = Policy_impl.to_json
let function_presets = Policy_impl.function_presets
let default_operators = Policy_impl.default_operators
let default_casts = Policy_impl.default_casts
let default_deny_casts = Policy_impl.default_deny_casts
