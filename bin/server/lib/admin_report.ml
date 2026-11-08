(* The server's shadow-mode analytics window (GET /v1/admin/report): Report_api
   instantiated with haltsql.report's live back end. *)

include Report_api.Make (Haltsql_report.Live)
