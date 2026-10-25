# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module IpScope
  # Thread-safe HTTP transport with persistent keep-alive Net::HTTP pooling,
  # streaming 2 MiB response ceiling, bounded JSON nesting depth (16),
  # and automatic exponential backoff with jitter.
  class HttpTransport
    DEFAULT_BASE_URL = "https://api.ipscope.io"
    DEFAULT_TIMEOUT_SECONDS = 5.0
    MAX_RESPONSE_BYTES = 2 * 1024 * 1024 # 2 MiB hard ceiling
    MAX_JSON_DEPTH = 16

    attr_reader :last_rate_limit

    def initialize(
      api_key:,
      base_url: DEFAULT_BASE_URL,
      timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
      retry_options: nil,
      user_agent: nil,
      custom_transport: nil
    )
      @api_key = Validator.validate_api_key(api_key)
      cleaned_base = base_url.to_s.strip
      cleaned_base = DEFAULT_BASE_URL if cleaned_base.empty?
      @base_url = cleaned_base.sub(%r{/+\z}, "")
      @base_uri = URI.parse(@base_url)
      @timeout_seconds = timeout_seconds.to_f.positive? ? timeout_seconds.to_f : DEFAULT_TIMEOUT_SECONDS
      @retry = retry_options || RetryOptions.new
      @user_agent = if user_agent && !user_agent.to_s.strip.empty?
                      user_agent.to_s.strip.freeze
                    else
                      "ipscope-sdk-ruby/#{VERSION} (Ruby/#{RUBY_VERSION})".freeze
                    end
      @custom_transport = custom_transport
      @http_mutex = Mutex.new
      @http_conn = nil
      @last_rate_limit = nil
    end

    def close
      @http_mutex.synchronize do
        if @http_conn && @http_conn.started?
          begin
            @http_conn.finish
          rescue StandardError
            # Ignore socket close errors on shutdown
          end
        end
        @http_conn = nil
        @last_rate_limit = nil
      end
    end

    # Executes an HTTP request and returns `{ data: Hash, rate_limit: RateLimitMetadata|nil }`.
    def request_json(method, path, json_body: nil, options: nil)
      normalized_path = path.to_s.start_with?("/") ? path.to_s : "/#{path}"
      url = "#{@base_url}#{normalized_path}"
      timeout = options&.timeout_seconds || @timeout_seconds

      headers = {
        "Accept" => "application/json",
        "X-API-Key" => @api_key,
        "User-Agent" => @user_agent
      }
      options&.headers&.each { |k, v| headers[k.to_s] = v.to_s }

      encoded_body = nil
      unless json_body.nil?
        headers["Content-Type"] = "application/json"
        encoded_body = JSON.generate(json_body)
      end

      max_attempts = [@retry.max_retries + 1, 1].max
      attempt = 0

      while attempt < max_attempts
        raw_resp = execute_raw(method.to_s.upcase, normalized_path, url, headers, encoded_body, timeout)
        status = raw_resp[:status]
        resp_headers = raw_resp[:headers]
        raw_body = raw_resp[:body]

        rate_limit = self.class.extract_rate_limit_metadata(resp_headers)
        @last_rate_limit = rate_limit unless rate_limit.nil?

        if status >= 200 && status < 300
          decoded = decode_bounded_json(raw_body, normalized_path, status, rate_limit)
          return {
            data: decoded,
            rate_limit: rate_limit
          }
        end

        retryable = [429, 502, 503, 504].include?(status)
        retry_after_sec = self.class.parse_retry_after_seconds(resp_headers["retry-after"])

        if retryable && (attempt + 1) < max_attempts
          delay_sec = compute_backoff_seconds(attempt, retry_after_sec)
          sleep(delay_sec) if delay_sec.positive?
          attempt += 1
          next
        end

        raise_mapped_api_error(status, normalized_path, raw_body, rate_limit, retry_after_sec)
      end

      raise IpScopeApiError.new("Exhausted retry attempts", status: 503, path: normalized_path)
    end

    def self.extract_rate_limit_metadata(headers)
      limit = parse_header_int(headers["x-ratelimit-limit"])
      remaining = parse_header_int(headers["x-ratelimit-remaining"])
      reset = parse_header_int(headers["x-ratelimit-reset"])
      credits = parse_header_int(headers["x-ratelimit-credits-remaining"])
      tier_raw = headers["x-ratelimit-tier"].to_s.strip
      tier = tier_raw.empty? ? nil : tier_raw

      return nil if limit.nil? && remaining.nil? && reset.nil? && credits.nil? && tier.nil?

      RateLimitMetadata.new(
        limit: limit,
        remaining: remaining,
        reset_epoch_seconds: reset,
        credits_remaining: credits,
        plan_tier: tier
      )
    end

    def self.parse_header_int(raw)
      return nil if raw.nil?

      trimmed = raw.to_s.strip
      return nil if trimmed.empty? || !/\A-?\d+\z/.match?(trimmed)

      trimmed.to_i
    end

    def self.parse_retry_after_seconds(raw)
      return nil if raw.nil?

      trimmed = raw.to_s.strip
      return nil if trimmed.empty? || !/\A\d+(\.\d+)?\z/.match?(trimmed)

      val = trimmed.to_f
      val >= 0.0 ? val : nil
    end

    private

    def execute_raw(method, path, url, headers, body, timeout_seconds)
      if @custom_transport
        res = @custom_transport.call(method, url, headers, body, timeout_seconds)
        raw_body = (res[:body] || res["body"] || "").to_s
        if raw_body.bytesize > MAX_RESPONSE_BYTES
          raise IpScopeApiError.new(
            format("IPScope response exceeded maximum allowed size of %d bytes", MAX_RESPONSE_BYTES),
            status: 502,
            path: path,
            error_code: "IPSCOPE_RESPONSE_TOO_LARGE"
          )
        end
        norm_headers = {}
        (res[:headers] || res["headers"] || {}).each do |k, v|
          norm_headers[k.to_s.downcase] = v.to_s
        end
        return {
          status: (res[:status] || res["status"] || 500).to_i,
          headers: norm_headers,
          body: raw_body
        }
      end

      uri = URI.parse(url)
      req = build_net_http_request(method, uri, headers, body)

      @http_mutex.synchronize do
        conn = ensure_http_connection(timeout_seconds)
        conn.open_timeout = [timeout_seconds, 3.0].min
        conn.read_timeout = timeout_seconds
        conn.write_timeout = timeout_seconds if conn.respond_to?(:write_timeout=)

        chunks = []
        received_bytes = 0
        resp_headers = {}
        status_code = 500

        begin
          conn.request(req) do |response|
            status_code = response.code.to_i
            response.each_header do |k, v|
              resp_headers[k.to_s.downcase] = v.to_s
            end

            response.read_body do |chunk|
              received_bytes += chunk.bytesize
              if received_bytes > MAX_RESPONSE_BYTES
                raise IpScopeApiError.new(
                  format("IPScope response exceeded maximum allowed size of %d bytes", MAX_RESPONSE_BYTES),
                  status: 502,
                  path: path,
                  error_code: "IPSCOPE_RESPONSE_TOO_LARGE"
                )
              end
              chunks << chunk
            end
          end
        rescue Net::OpenTimeout, Net::ReadTimeout, Net::WriteTimeout
          reset_http_connection_unlocked
          raise IpScopeTimeoutError.new(path, timeout_seconds)
        rescue IpScopeError
          reset_http_connection_unlocked
          raise
        rescue StandardError => e
          reset_http_connection_unlocked
          raise IpScopeApiError.new(
            format("Network error communicating with IPScope API (%s): %s", path, e.message),
            status: 503,
            path: path,
            error_code: "IPSCOPE_NETWORK_ERROR"
          )
        end

        {
          status: status_code,
          headers: resp_headers,
          body: chunks.join
        }
      end
    end

    def ensure_http_connection(timeout_seconds)
      if @http_conn.nil? || !@http_conn.started?
        http = Net::HTTP.new(@base_uri.host, @base_uri.port)
        http.use_ssl = (@base_uri.scheme == "https")
        http.keep_alive_timeout = 30
        http.open_timeout = [timeout_seconds, 3.0].min
        http.read_timeout = timeout_seconds
        http.start
        @http_conn = http
      end
      @http_conn
    end

    def reset_http_connection_unlocked
      if @http_conn && @http_conn.started?
        begin
          @http_conn.finish
        rescue StandardError
          # Ignore close errors
        end
      end
      @http_conn = nil
    end

    def build_net_http_request(method, uri, headers, body)
      request_path = uri.request_uri
      klass = case method
              when "GET" then Net::HTTP::Get
              when "POST" then Net::HTTP::Post
              when "PUT" then Net::HTTP::Put
              when "DELETE" then Net::HTTP::Delete
              else Net::HTTP::Get
              end
      req = klass.new(request_path)
      headers.each { |k, v| req[k] = v }
      req.body = body unless body.nil?
      req
    end

    def decode_bounded_json(raw_body, path, status, rate_limit)
      parsed = JSON.parse(raw_body, max_nesting: MAX_JSON_DEPTH)
      unless parsed.is_a?(Hash)
        raise IpScopeApiError.new(
          "Expected JSON object response from IPScope API.",
          status: status,
          path: path,
          error_code: "IPSCOPE_INVALID_JSON",
          rate_limit: rate_limit
        )
      end
      parsed
    rescue JSON::JSONError => e
      raise IpScopeApiError.new(
        "Invalid or excessively nested JSON received from IPScope API: #{e.message}",
        status: status,
        path: path,
        error_code: "IPSCOPE_INVALID_JSON",
        rate_limit: rate_limit
      )
    end

    def compute_backoff_seconds(attempt, retry_after_seconds)
      if retry_after_seconds && retry_after_seconds.positive?
        return [retry_after_seconds, @retry.max_delay_seconds].min
      end

      exp = @retry.initial_delay_seconds * (2**attempt)
      capped = [exp, @retry.max_delay_seconds].min
      jitter = 0.75 + (rand * 0.25)
      capped * jitter
    end

    def raise_mapped_api_error(status, path, raw_body, rate_limit, retry_after_seconds)
      message = format('IPScope API request to "%s" failed with HTTP %d', path, status)
      error_code = "IPSCOPE_HTTP_#{status}"

      if !raw_body.to_s.empty? && raw_body.bytesize <= 65_536
        begin
          parsed = JSON.parse(raw_body, max_nesting: 8)
          if parsed.is_a?(Hash)
            if parsed["message"].is_a?(String) && !parsed["message"].strip.empty?
              message = parsed["message"]
            elsif parsed["error"].is_a?(String) && !parsed["error"].strip.empty?
              message = parsed["error"]
            end
            error_code = parsed["code"] if parsed["code"].is_a?(String)
          end
        rescue JSON::JSONError
          # Keep default message
        end
      end

      if status == 401 || status == 403
        raise IpScopeAuthenticationError.new(message, status: status, path: path, rate_limit: rate_limit)
      end
      if status == 429
        raise IpScopeRateLimitError.new(
          message,
          path: path,
          retry_after_seconds: retry_after_seconds,
          rate_limit: rate_limit
        )
      end

      raise IpScopeApiError.new(
        message,
        status: status,
        path: path,
        error_code: error_code,
        rate_limit: rate_limit
      )
    end
  end
end
