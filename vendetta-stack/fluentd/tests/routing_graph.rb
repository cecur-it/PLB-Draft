#!/usr/bin/env ruby
# Traces: PROMPT §4.3 telemetry-loop prevention, §5; CONTRACT §3, §5. Static routing proof for the Fluentd aggregator config.
# Uses Fluentd's OWN config parser (embedded Ruby, @include, labels) and MatchPattern, then walks the match/copy/relabel graph for every
# tag the pipeline can see and compares the set of terminal outputs (@id) with an expectation table. Exit 1 on any violation.
# Usage (inside the fluentd image, after entrypoint rendering):  ruby routing_graph.rb /fluentd/etc/fluent.conf [--json]
require 'json'
require 'fluent/config'
require 'fluent/match'

NON_RETAGGING_FILTERS = %w[grep record_transformer record_modifier prometheus].freeze
OLLAMA_ONLY = %w[esoc-otlp esoc-otlp-disabled siem-ndjson siem-ndjson-disabled].freeze
OPENSEARCH = %w[opensearch opensearch-errow opensearch-errow-findings opensearch-errow-alerts opensearch-cfgaudit-findings opensearch-cfgaudit-runs opensearch-llm-audit opensearch-llm-inference].freeze
GATED_HTTP = %w[http-llm-triage http-feedback-loop http-errow-cloud http-vendetta-execd].freeze

class Graph
  attr_reader :violations

  def initialize(root)
    @root = root
    @labels = root.elements.select { |e| e.name == 'label' }.to_h { |e| [e.arg, e] }
    @violations = []
  end

  def terminals(tag)
    out = { ids: [], labels: [] }
    walk(tag, @root, 'ROOT', out, [])
    out[:ids].uniq!
    out
  end

  private

  def walk(tag, scope, scope_name, out, seen)
    key = [tag, scope_name]
    return if seen.include?(key)

    seen << key
    out[:labels] << scope_name
    check_filters(tag, scope, scope_name)
    m = scope.elements.select { |e| e.name == 'match' }.find do |e|
      e.arg.split(/\s+/).any? { |pat| Fluent::MatchPattern.create(pat).match(tag) }
    end
    if m.nil?
      out[:ids] << "(unmatched in #{scope_name})"
      return
    end
    follow(m, tag, out, seen)
  end

  def follow(el, tag, out, seen)
    case el['@type']
    when 'relabel'
      label = el['@label']
      if @labels[label]
        walk(tag, @labels[label], label, out, seen)
      else
        @violations << "relabel to undefined label #{label}"
      end
    when 'copy'
      el.elements.select { |e| e.name == 'store' }.each { |s| follow(s, tag, out, seen) }
    when 'rewrite_tag_filter'
      @violations << "#{el['@id']}: rewrite_tag_filter on the routed path makes the static proof unsound"
    when 'prometheus'
      out[:ids] << 'prometheus-metric'
    else
      out[:ids] << (el['@id'] || el['@type'])
    end
  end

  def check_filters(tag, scope, scope_name)
    scope.elements.select { |e| e.name == 'filter' }.each do |f|
      next unless f.arg.split(/\s+/).any? { |pat| Fluent::MatchPattern.create(pat).match(tag) }
      next if NON_RETAGGING_FILTERS.include?(f['@type'])

      @violations << "filter #{f['@type']} in #{scope_name} may rewrite tags; not covered by the static proof"
    end
  end
end

path = ARGV.shift or abort('usage: routing_graph.rb <fluent.conf> [--json]')
root = Fluent::Config.parse(File.read(path), path, File.dirname(path), true)
graph = Graph.new(root)

TAGS = %w[
  vendetta.alerts vendetta.fim vendetta.vulnerability vendetta.sca
  errow.findings errow.runs errow.coverage errow.llm_logs errow.threat_models errow.mcp_events errow.runtime_events errow.proxy
  errow.tui_events errow.cloud_events errow.telemetry errow.agent_state errow.viewer errow.report_artifacts
  cfgaudit.findings cfgaudit.runs cfgaudit.future_stream
  cs3.ai.inference cs3.ai.tool_call cs3.ai.enrichment cs3.ai.ollama cs3.ai.future_stream
  cs3.sp.vendetta_alert_rate cs3.sp.ai_ollama host.journal host.auth v1_logs some.unknown.tag
].freeze

result = TAGS.to_h { |t| [t, graph.terminals(t)] }
failures = graph.violations.dup

def expect(failures, tag, ids, must: [], must_not: [], only: nil)
  must.each { |m| failures << "#{tag}: expected to reach #{m}, got #{ids.sort}" unless ids.include?(m) }
  must_not.each { |m| failures << "#{tag}: MUST NOT reach #{m} (got #{ids.sort})" if ids.include?(m) }
  return unless only
  extra = ids - only
  failures << "#{tag}: reaches outputs outside the allowed set #{only.sort}: #{extra.sort}" unless extra.empty?
end

ids = ->(t) { result[t][:ids] }

# Telemetry-loop invariant (PROMPT §4.3): Ollama journald lines reach ESOC + SIEM and nothing else.
expect(failures, 'cs3.ai.ollama', ids.('cs3.ai.ollama'), only: OLLAMA_ONLY)
failures << 'cs3.ai.ollama: no ESOC/SIEM output reached' if (ids.('cs3.ai.ollama') & OLLAMA_ONLY).empty?
expect(failures, 'cs3.ai.ollama', ids.('cs3.ai.ollama'), must_not: OPENSEARCH + GATED_HTTP)
%w[host.journal host.auth v1_logs].each { |t| expect(failures, t, ids.(t), only: OLLAMA_ONLY) }

%w[vendetta.alerts vendetta.fim vendetta.vulnerability vendetta.sca].each do |t|
  expect(failures, t, ids.(t), must: %w[opensearch http-llm-triage], must_not: %w[http-feedback-loop opensearch-llm-audit] + %w[esoc-otlp siem-ndjson])
end
expect(failures, 'errow.findings', ids.('errow.findings'),
       must: %w[opensearch-errow-findings opensearch-errow opensearch-errow-alerts http-feedback-loop http-llm-triage http-vendetta-execd],
       must_not: %w[opensearch-llm-audit esoc-otlp siem-ndjson])
(%w[errow.runs errow.coverage errow.llm_logs errow.threat_models errow.mcp_events errow.runtime_events errow.proxy errow.tui_events
    errow.cloud_events errow.telemetry errow.agent_state errow.viewer errow.report_artifacts]).each do |t|
  expect(failures, t, ids.(t), only: %w[opensearch-errow])
end
expect(failures, 'cfgaudit.findings', ids.('cfgaudit.findings'), only: %w[opensearch-cfgaudit-findings])
expect(failures, 'cfgaudit.runs', ids.('cfgaudit.runs'), only: %w[opensearch-cfgaudit-runs])
expect(failures, 'cfgaudit.future_stream', ids.('cfgaudit.future_stream'), only: %w[dead_letter_unrouted])
expect(failures, 'cs3.ai.inference', ids.('cs3.ai.inference'),
       must: %w[opensearch-llm-inference opensearch-llm-audit opensearch], must_not: GATED_HTTP)
expect(failures, 'cs3.ai.tool_call', ids.('cs3.ai.tool_call'),
       must: %w[opensearch-errow opensearch-llm-audit], must_not: GATED_HTTP)
expect(failures, 'cs3.ai.enrichment', ids.('cs3.ai.enrichment'), only: %w[opensearch])
# Anything under cs3.ai.* (even a tag nobody knows yet) can never be sent back to the gateway or to any HTTP action leg.
expect(failures, 'cs3.ai.future_stream', ids.('cs3.ai.future_stream'), must_not: GATED_HTTP + %w[esoc-otlp siem-ndjson])
expect(failures, 'some.unknown.tag', ids.('some.unknown.tag'), only: %w[dead_letter_unrouted])
%w[cs3.sp.vendetta_alert_rate cs3.sp.ai_ollama].each do |t|
  expect(failures, t, ids.(t), must_not: OPENSEARCH + GATED_HTTP)
end

if ARGV.include?('--json')
  puts JSON.pretty_generate(result)
else
  result.each { |t, r| puts format('%-28s -> %s', t, r[:ids].sort.join(', ')) }
end
if failures.empty?
  puts "ROUTING OK: #{TAGS.size} tags checked"
else
  failures.each { |f| warn "ROUTING VIOLATION: #{f}" }
  exit 1
end
