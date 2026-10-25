# frozen_string_literal: true

module IpScope
  # Thread-safe bounded O(1) LRU + TTL in-memory cache for IP intelligence records.
  #
  # Uses Ruby's insertion-ordered Hash (`delete(key)` + `store[key] = entry`,
  # `store.shift` for O(1) eviction of the least-recently-used key) protected by a `Mutex`.
  class LruTtlCache
    def initialize(options = nil)
      opts = options || CacheOptions.new
      @enabled = opts.enabled && opts.max_entries.positive? && opts.ttl_seconds.positive?
      @max_entries = [opts.max_entries, 1].max
      @ttl_seconds = [opts.ttl_seconds, 0.001].max
      @mutex = Mutex.new
      @store = {}
      @hits = 0
      @misses = 0
      @evictions = 0
    end

    def enabled?
      @enabled
    end

    def get(key, now_monotonic = nil)
      return nil unless @enabled

      now = now_monotonic || monotonic_now
      @mutex.synchronize do
        entry = @store[key]
        unless entry
          @misses += 1
          return nil
        end

        if now >= entry[:expires_at]
          @store.delete(key)
          @misses += 1
          return nil
        end

        # Promote to most-recently-used tail in O(1)
        @store.delete(key)
        @store[key] = entry
        @hits += 1
        entry[:value]
      end
    end

    def set(key, value, now_monotonic = nil)
      return unless @enabled

      now = now_monotonic || monotonic_now
      @mutex.synchronize do
        if @store.key?(key)
          @store.delete(key)
        elsif @store.length >= @max_entries
          @store.shift
          @evictions += 1
        end

        @store[key] = {
          value: value,
          expires_at: now + @ttl_seconds
        }
      end
    end

    def clear
      @mutex.synchronize do
        @store.clear
        @hits = 0
        @misses = 0
        @evictions = 0
      end
    end

    def stats
      @mutex.synchronize do
        CacheStats.new(
          enabled: @enabled,
          size: @store.length,
          max_entries: @max_entries,
          hits: @hits,
          misses: @misses,
          evictions: @evictions
        )
      end
    end

    private

    def monotonic_now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
