#!/usr/bin/env ruby
# Structural lint for TestSuite corpus files (does not run HaltSQL).
# Usage: ruby -ryaml test/corpus/check_suites.rb test/corpus/*.suite.yaml ...
# Checks: document shape, policy path exists, unique case names, valid expect,
# codes drawn from Reason.all_codes, allow cases have no codes, deny cases on a
# bound-mode policy never carry `bind`. Prints per-file counts.
require 'yaml'
require 'json'

CODES = %w[E_PARSE E_EMPTY E_LIMIT E_MULTI_STATEMENT E_STATEMENT_KIND
  E_DATA_MODIFYING_CTE E_TABLE_DENIED E_COLUMN_DENIED E_COLUMN_UNRESOLVED
  E_FUNCTION_DENIED E_OPERATOR_DENIED E_CAST_DENIED E_TENANT_MISSING
  E_TENANT_MISMATCH E_TENANT_WRITE E_CONTEXT_MISSING E_PARAM_UNBOUND
  E_LIMIT_REQUIRED E_LIMIT_TOO_HIGH E_LOCKING_CLAUSE E_SELECT_INTO
  E_JOIN_BUDGET E_WRITE_DENIED E_UNSUPPORTED E_INTERNAL]

errors = []
total = 0
totals = Hash.new(0)
ARGV.each do |f|
  doc = f.end_with?('.json') ? JSON.parse(File.read(f)) : YAML.load_file(f)
  e = ->(m) { errors << "#{f}: #{m}" }
  e.("apiVersion") unless doc['apiVersion'] == 'haltsql.dev/v1'
  e.("kind") unless doc['kind'] == 'TestSuite'
  e.("metadata.name") unless doc.dig('metadata', 'name').is_a?(String)
  extra = doc.keys - %w[apiVersion kind metadata policy defaults cases]
  e.("unknown top-level keys #{extra}") unless extra.empty?
  pol = File.expand_path(doc['policy'].to_s, File.dirname(f))
  e.("policy not found: #{pol}") unless File.file?(pol)
  names = {}
  allow = deny = 0
  (doc['cases'] || []).each_with_index do |c, i|
    where = "case ##{i} #{c['name'].inspect}"
    bad = c.keys - %w[name sql context expect codes bind tags]
    e.("#{where}: unknown keys #{bad}") unless bad.empty?
    e.("#{where}: missing name") unless c['name'].is_a?(String) && !c['name'].empty?
    e.("#{where}: duplicate name") if names[c['name']]
    names[c['name']] = true
    e.("#{where}: sql must be a string") unless c['sql'].is_a?(String)
    case c['expect']
    when 'allow'
      allow += 1
      e.("#{where}: allow with codes") if c['codes'] && !c['codes'].empty?
    when 'deny'
      deny += 1
      e.("#{where}: deny with bind") if c['bind']
    else e.("#{where}: bad expect #{c['expect'].inspect}")
    end
    (c['codes'] || []).each { |k| e.("#{where}: unknown code #{k}") unless CODES.include?(k) }
    (c['bind'] || []).each do |b|
      e.("#{where}: bad bind #{b}") unless b.is_a?(Hash) && b['param'].is_a?(Integer) && b.key?('value')
    end
    e.("#{where}: tags must be a list") if c['tags'] && !c['tags'].is_a?(Array)
  end
  n = allow + deny
  total += n
  totals[:allow] += allow
  totals[:deny] += deny
  printf("%-55s %4d cases (%d allow, %d deny)\n", f, n, allow, deny)
rescue StandardError => ex
  errors << "#{f}: #{ex.class}: #{ex.message}"
end
printf("TOTAL %d cases (%d allow, %d deny)\n", total, totals[:allow], totals[:deny])
unless errors.empty?
  puts errors
  exit 1
end
