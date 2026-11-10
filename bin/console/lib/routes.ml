(* Every feature's routes and background loops. Adding a feature = one line in each list. *)

let all : Router.route list =
  List.concat
    [
      Access.routes;
      Activity.routes;
      Overview.routes;
      Signals.routes;
      Cases.routes;
      Records.routes;
      Agents.routes;
      Playground.routes;
      Policies.routes;
      Fleet.routes;
      Data.routes;
      Evidence.routes;
    ]

let background : (string * (Ctx.t -> unit Lwt.t)) list =
  [
    ("ingest", Ingest.start);
    ("fleet", Fleet.start);
    ("policies", Policies.start);
    ("signals", Signals.start);
    ("data", Data.start);
    ("records", Records.start);
    ("overview", Overview.start);
    ("cases", Cases.start);
    ("agents", Agents.start);
    ("playground", Playground.start);
    ("evidence", Evidence.start);
  ]
