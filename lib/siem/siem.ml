module Config = Haltsql_load.Config

let sanitize s =
  let s =
    String.map
      (fun c ->
        if
          (c >= 'a' && c <= 'z')
          || (c >= 'A' && c <= 'Z')
          || (c >= '0' && c <= '9')
          || c = '-' || c = '.'
        then c
        else '_')
      s
  in
  if s = "" then "unknown" else if String.length s > 63 then String.sub s 0 63 else s

let created = ref 0

let default_run_id now =
  let n = !created in
  incr created;
  let t = now () in
  let tm = Unix.gmtime t in
  let us = int_of_float ((t -. Float.of_int (int_of_float t)) *. 1e6) in
  Printf.sprintf "%04d%02d%02dT%02d%02d%02d.%06dZ.%d" (tm.tm_year + 1900) (tm.tm_mon + 1)
    tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec
    (max 0 (min 999_999 us))
    (Unix.getpid ())
  ^ if n = 0 then "" else Printf.sprintf ".%d" n

let chain_id ~host ~run_id =
  Printf.sprintf "haltsql/%s/%s" (sanitize host) (sanitize run_id)

let of_config ?(now = Unix.gettimeofday) ?host ?run_id ?max_attempts ?base_backoff
    ?max_backoff ?(on_event = ignore) (s : Config.stream_sink) =
  let host =
    match host with
    | Some h -> h
    | None -> ( try Unix.gethostname () with _ -> "unknown")
  in
  let run_id = match run_id with Some r -> r | None -> default_run_id now in
  let make ~name ~kind ~batch ?prepare ~close_transport deliver =
    Stream_sink.create ~now ?max_attempts ?base_backoff ?max_backoff ?prepare
      ~close_transport ~on_event ~name ~kind ~batch ~on_error:s.stream_on_error
      ~max_buffer_records:s.max_buffer_records deliver
  in
  match s.stream with
  | Config.Stream_elasticsearch es -> (
      let open Lwt.Infix in
      Es_sink.create es >|= function
      | Error m -> Error m
      | Ok t ->
          make ~name:(Es_sink.name es) ~kind:"elasticsearch" ~batch:es.es_batch
            ~prepare:Es_sink.prepare
            ~close_transport:(fun () -> Lwt.return_unit)
            (Es_sink.deliver t))
  | Config.Stream_kafka k ->
      Lwt.return
        (match Kafka_sink.create ~on_event ~key:(chain_id ~host ~run_id) k with
        | Error m -> Error m
        | Ok t ->
            make ~name:(Kafka_sink.name k) ~kind:"kafka" ~batch:k.kafka_batch
              ~close_transport:(fun () -> Kafka_sink.close t)
              (Kafka_sink.deliver t))

let metrics_text = Stream_sink.metrics_text
