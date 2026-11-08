# Renders the HaltSQL policy CI Markdown summary.
# Inputs (via --slurpfile / --arg):
#   $validate : [validate --json output]  ([] when validate could not run)
#   $lint     : [[lint-policy --json output + {file}, one per policy]]
#   $tests    : [test --json output]      ([] when there are no suites)
#   $failwarn : "true" | "false"
#   $max_denied : max denied cases listed per suite (string number)

def esc: tostring
  | gsub("&"; "&amp;") | gsub("<"; "&lt;") | gsub(">"; "&gt;")
  | gsub("\\|"; "&#124;") | gsub("`"; "&#96;") | gsub("[\r\n]+"; " ");
def code: "`" + (tostring | gsub("`"; "'")) + "`";

($validate[0] // null) as $v
| ($tests[0] // null) as $t
| ($lint[0] // []) as $lints
| ($lints | map(.findings // [] | map(select(.severity == "warning"))) | add // []) as $warnings
| ($v != null and $v.ok == true) as $valid
| ($t == null or ($t.ok == true)) as $tests_ok
| (($failwarn == "true") and ($warnings | length) > 0) as $warn_fail
| ($valid and $tests_ok and ($warn_fail | not)) as $ok
| [
    "<!-- haltsql-policy-ci -->",
    "## HaltSQL policy CI: " + (if $ok then "PASS" else "FAIL" end),
    "",
    "| Check | Result |",
    "| --- | --- |",
    ("| Validate | "
      + (if $v == null then "did not run"
         else "\($v.files | length) file(s), \($v.files | map(select(.ok | not)) | length) with errors"
         end)
      + " |"),
    ("| Lint | \($warnings | length) warning(s) in \($lints | length) policy file(s)"
      + (if $warn_fail then " (fail-on-warnings)" else "" end) + " |"),
    ("| Tests | "
      + (if $t == null then "no suites"
         else "\($t.suites | length) suite(s): \($t.passed) passed, \($t.failed) failed"
           + (if ($t.load_errors // 0) > 0 then ", \($t.load_errors) failed to load" else "" end)
         end)
      + " |"),
    ""
  ]
  + (if $v != null and ($v.files | map(select(.ok | not)) | length) > 0 then
      ["### Validation errors", ""]
      + [ $v.files[] | select(.ok | not) | .file as $f | .errors[]
          | "- " + ($f | code) + ": "
            + (if .line then "line \(.line): " else "" end)
            + (if (.path // "") != "" then (.path | code) + ": " else "" end)
            + (.message | esc) ]
      + [""]
    else [] end)
  + (if $t != null and ($t.suites | length) > 0 then
      ["### Test suites", "", "| Suite | File | Passed | Failed | Result |", "| --- | --- | --- | --- | --- |"]
      + [ $t.suites[]
          | if .errors then
              "| (load error) | \(.file | esc) | 0 | 0 | ERROR |"
            else
              "| \(.name | esc) | \(.file | esc) | \(.passed) | \(.failed) | "
              + (if .failed == 0 then "pass" else "**FAIL**" end) + " |"
            end ]
      + [""]
    else [] end)
  + (if $t != null and ([ $t.suites[] | select(.errors) ] | length) > 0 then
      ["### Suites that failed to load", ""]
      + [ $t.suites[] | select(.errors) | .file as $f | .errors[]
          | "- " + ($f | code) + ": " + (.message | esc) ]
      + [""]
    else [] end)
  + (if $t != null and ([ $t.suites[] | select(.cases) | .cases[] | select(.passed | not) ] | length) > 0 then
      ["### Failed cases", "", "| Suite | Case | Problem | Reasons |", "| --- | --- | --- | --- |"]
      + [ $t.suites[] | select(.cases) | .name as $s | .cases[] | select(.passed | not)
          | "| \($s | esc) | \(.name | esc) | \((.failure // "failed") | esc) | "
            + ((.verdict.reasons // []) | map(.code | code) | join(" ")) + " |" ]
      + [""]
    else [] end)
  + (if $t != null and ([ $t.suites[] | select(.cases) | .cases[] | select(.verdict.allowed == false) ] | length) > 0 then
      ["### Denied cases", ""]
      + [ $t.suites[] | select(.cases)
          | . as $suite
          | [ .cases[] | select(.verdict.allowed == false) ] as $denied
          | select(($denied | length) > 0)
          | ( "<details><summary>\($suite.name | esc): \($denied | length) denied case(s)</summary>",
              "",
              "| Case | Expected | Codes | First reason |",
              "| --- | --- | --- | --- |",
              ( $denied[: ($max_denied | tonumber)][]
                | "| \(.name | esc) | " + (if .passed then "yes" else "**no**" end) + " | "
                  + ((.verdict.reasons // []) | map(.code | code) | join(" ")) + " | "
                  + (((.verdict.reasons // [])[0].message // "") | esc) + " |" ),
              (if ($denied | length) > ($max_denied | tonumber)
               then "", "... \(($denied | length) - ($max_denied | tonumber)) more" else empty end),
              "",
              "</details>",
              "" ) ]
    else [] end)
  + (if ($warnings | length) > 0 then
      ["### Lint warnings", ""]
      + [ $lints[] | .policy as $p | (.findings // [])[] | select(.severity == "warning")
          | "- " + ($p | esc) + ": " + (.code | code) + " " + (.message | esc) ]
      + [""]
    else [] end)
| .[]
