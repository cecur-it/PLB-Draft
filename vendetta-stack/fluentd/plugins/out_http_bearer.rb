# Traces: PROMPT §1 Tier 2 (secrets only via files), CONTRACT §5 (http-llm-triage / http-feedback-loop / siem-ndjson), §13
# `@type http_bearer`: core out_http (Fluentd 1.17) plus `bearer_token_file` / `bearer_scheme`.
# Why: core out_http has no token auth, and putting "Authorization: Bearer <token>" into the `headers` parameter would print the
# token in Fluentd's startup configuration dump. Here the token is read from the secret file on EVERY request, so it never appears
# in the config and a rotated secret file is picked up without a restart. An empty/unset bearer_token_file sends no Authorization
# header (mTLS-only endpoints).

require 'fluent/plugin/out_http'

module Fluent::Plugin
  class HTTPBearerOutput < HTTPOutput
    Fluent::Plugin.register_output('http_bearer', self)

    desc 'File holding the token (whitespace trimmed); sent as "Authorization: <bearer_scheme> <token>"'
    config_param :bearer_token_file, :string, default: nil
    desc 'Authorization scheme placed before the token'
    config_param :bearer_scheme, :string, default: 'Bearer'

    def configure(conf)
      super
      @bearer_token_file = nil if @bearer_token_file.to_s.strip.empty?
      return unless @bearer_token_file
      raise Fluent::ConfigError, "bearer_token_file is not readable: #{@bearer_token_file}" unless File.file?(@bearer_token_file) && File.readable?(@bearer_token_file)
    end

    # Output#implement? only inspects methods defined on the concrete class, so `format` (custom_format) and `write` (buffered)
    # must be (re)declared here; without `format` the buffer would hold raw msgpack and the <format> section would be ignored.
    def format(tag, time, record)
      super
    end

    def write(chunk)
      super
    end

    private

    def set_headers(req, uri, chunk)
      super
      return unless @bearer_token_file

      token = File.read(@bearer_token_file).strip
      raise ArgumentError, "bearer_token_file is empty: #{@bearer_token_file}" if token.empty?

      req['Authorization'] = "#{@bearer_scheme} #{token}"
    end
  end
end
