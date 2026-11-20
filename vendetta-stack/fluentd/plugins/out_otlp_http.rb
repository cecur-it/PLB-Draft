# Traces: PROMPT §1 Tier 2 (ESOC OTLP leg), CONTRACT §5 (@id esoc-otlp), §8.3 Leg2
# `@type otlp_http`: one OTLP/HTTP JSON `ExportLogsServiceRequest` (POST <endpoint>/v1/logs) per buffer chunk, with mTLS and a
# bearer token read from a file (inherited from http_bearer / core out_http).
# Why a plugin of our own: `fluent-plugin-opentelemetry` needs the native `grpc` gem (compiler + ~60 MB) which the pinned base image
# cannot build, and the ESOC gateway accepts OTLP over HTTP/JSON as well as gRPC. Fluent Bit keeps the gRPC leg on the edge.
# Mapping: record["@timestamp"]/event time -> timeUnixNano; severity (vendetta: critical|high|medium|low|info, journald: PRIORITY)
# -> severityNumber/Text; MESSAGE|message|full_log -> body; every other top-level key -> attributes (nested values as JSON strings).
# Delivery: 429/5xx retry (retryable_response_codes), other 4xx are unrecoverable and the chunk goes to <secondary>.

require 'json'
require 'time'
require 'zlib'
require 'stringio'
require_relative 'out_http_bearer'

module Fluent::Plugin
  class OtlpHttpOutput < HTTPBearerOutput
    Fluent::Plugin.register_output('otlp_http', self)

    SEVERITY = {
      'critical' => [21, 'FATAL'], 'high' => [17, 'ERROR'], 'medium' => [13, 'WARN'], 'low' => [9, 'INFO'], 'info' => [9, 'INFO']
    }.freeze
    PRIORITY = {
      0 => [21, 'FATAL'], 1 => [21, 'FATAL'], 2 => [21, 'FATAL'], 3 => [17, 'ERROR'], 4 => [13, 'WARN'],
      5 => [9, 'INFO'], 6 => [9, 'INFO'], 7 => [5, 'DEBUG']
    }.freeze
    BODY_KEYS = %w[MESSAGE message full_log].freeze

    desc 'service.name resource attribute'
    config_param :service_name, :string, default: 'vendetta-stack-fluentd'
    desc 'service.instance.id resource attribute (the aggregator node)'
    config_param :instance_id, :string, default: nil
    desc 'instrumentation scope name'
    config_param :scope_name, :string, default: 'vendetta-stack/fluentd'
    desc 'Maximum characters kept for the log body'
    config_param :body_max_chars, :integer, default: 8000

    config_set_default :content_type, 'application/json'

    def configure(conf)
      super
      @resource = [attr('service.name', @service_name)]
      @resource << attr('service.instance.id', @instance_id) if @instance_id && !@instance_id.empty?
    end

    # One JSON line per event keeps the chunk newline-delimited, as in core out_http.
    def format(tag, time, record)
      JSON.generate('tag' => tag, 'sec' => time.to_i, 'nsec' => (time.respond_to?(:nsec) ? time.nsec : 0), 'record' => record) << "\n"
    end

    def write(chunk)
      super
    end

    private

    def create_request(chunk, uri)
      req = Net::HTTP::Post.new(uri.request_uri)
      set_headers(req, uri, chunk)
      events = chunk.read.each_line.map { |line| JSON.parse(line) rescue nil }.compact
      body = JSON.generate(export_request(events))
      if @compress == :gzip
        gz = Zlib::GzipWriter.new(StringIO.new)
        gz << body
        body = gz.close.string
      end
      req.body = body
      req
    end

    def export_request(events)
      {
        'resourceLogs' => [{
          'resource' => { 'attributes' => @resource },
          'scopeLogs' => [{
            'scope' => { 'name' => @scope_name },
            'logRecords' => events.map { |e| log_record(e) }
          }]
        }]
      }
    end

    def log_record(event)
      rec = event['record'].is_a?(Hash) ? event['record'] : { 'message' => event['record'].to_s }
      number, text = severity_of(rec)
      body_key = BODY_KEYS.find { |k| rec[k].is_a?(String) && !rec[k].empty? }
      body = body_key ? rec[body_key] : JSON.generate(rec)
      attrs = [attr('fluentd.tag', event['tag'].to_s)]
      rec.each do |k, v|
        next if k == body_key || v.nil?

        attrs << attr(k.to_s, v)
      end
      {
        'timeUnixNano' => time_unix_nano(rec, event),
        'severityNumber' => number,
        'severityText' => text,
        'body' => { 'stringValue' => body.to_s.scrub[0, @body_max_chars] },
        'attributes' => attrs
      }
    end

    def severity_of(rec)
      sev = rec['severity'].to_s.downcase
      return SEVERITY[sev] if SEVERITY.key?(sev)

      pri = Integer(rec['PRIORITY'].to_s, 10) rescue nil
      PRIORITY.fetch(pri, [9, 'INFO'])
    end

    def time_unix_nano(rec, event)
      t = rec['@timestamp'].to_s
      unless t.empty?
        parsed = Time.iso8601(t) rescue nil
        return ((parsed.to_i * 1_000_000_000) + parsed.nsec).to_s if parsed
      end
      ((event['sec'].to_i * 1_000_000_000) + event['nsec'].to_i).to_s
    end

    def attr(key, value)
      v = case value
          when String then { 'stringValue' => value.scrub }
          when true, false then { 'boolValue' => value }
          when Integer then { 'intValue' => value.to_s }
          when Float then { 'doubleValue' => value }
          else { 'stringValue' => JSON.generate(value) }
          end
      { 'key' => key, 'value' => v }
    end
  end
end
