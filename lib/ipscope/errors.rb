# frozen_string_literal: true

module IpScope
  # Base error class for all exceptions raised by the IPScope Ruby SDK.
  class IpScopeError < StandardError
    attr_reader :error_code

    def initialize(message, error_code: "IPSCOPE_ERROR")
      super(message)
      @error_code = error_code.to_s.freeze
    end
  end

  # Raised when client-side validation fails before sending an HTTP request.
  class IpScopeValidationError < IpScopeError
    attr_reader :field

    def initialize(message, field: nil)
      super(message, error_code: "IPSCOPE_VALIDATION_ERROR")
      @field = field ? field.to_s.freeze : nil
    end
  end

  # Raised when an HTTP request exceeds the configured timeout.
  class IpScopeTimeoutError < IpScopeError
    attr_reader :path, :timeout_seconds

    def initialize(path, timeout_seconds)
      @path = path.to_s.freeze
      @timeout_seconds = timeout_seconds.to_f
      super(
        format('IPScope request to "%s" timed out after %.2fs', @path, @timeout_seconds),
        error_code: "IPSCOPE_TIMEOUT_ERROR"
      )
    end
  end

  # Raised when the IPScope API returns a non-2xx HTTP status code or network failure.
  class IpScopeApiError < IpScopeError
    attr_reader :status, :path, :rate_limit

    def initialize(message, status:, path:, error_code: nil, rate_limit: nil)
      @status = status.to_i
      @path = path.to_s.freeze
      @rate_limit = rate_limit
      super(message, error_code: error_code || "IPSCOPE_HTTP_#{@status}")
    end
  end

  # Raised on HTTP 401 Unauthorized or 403 Forbidden.
  class IpScopeAuthenticationError < IpScopeApiError
    def initialize(message, status:, path:, rate_limit: nil)
      code = status.to_i == 401 ? "IPSCOPE_UNAUTHORIZED" : "IPSCOPE_FORBIDDEN_SCOPE"
      super(message, status: status, path: path, error_code: code, rate_limit: rate_limit)
    end
  end

  # Raised on HTTP 429 Too Many Requests when retries are exhausted or disabled.
  class IpScopeRateLimitError < IpScopeApiError
    attr_reader :retry_after_seconds

    def initialize(message, path:, retry_after_seconds: nil, rate_limit: nil)
      @retry_after_seconds = retry_after_seconds ? retry_after_seconds.to_f : nil
      super(
        message,
        status: 429,
        path: path,
        error_code: "IPSCOPE_RATE_LIMITED",
        rate_limit: rate_limit
      )
    end
  end
end
