# frozen_string_literal: true

require_relative "lib/ipscope/version"

Gem::Specification.new do |spec|
  spec.name          = "ipscope"
  spec.version       = IpScope::VERSION
  spec.authors       = ["IPScope Engineering"]
  spec.email         = ["sdk@ipscope.io"]

  spec.summary       = "Official zero-dependency, memory-safe Ruby Server-Side SDK for the IPScope IP Intelligence Platform."
  spec.description   = "Server-side Ruby SDK for IPScope providing single IP lookup, batch lookup, constant-RAM streaming batch lookup, CIDR network prefix lookup, dataset metadata, feedback submission, bounded O(1) LRU caching, and singleflight request coalescing."
  spec.homepage      = "https://ipscope.io"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["homepage_uri"]      = spec.homepage
  spec.metadata["source_code_uri"]   = "https://github.com/ipscope-io/ipscope-ruby"
  spec.metadata["documentation_uri"] = "https://ipscope.io/docs/sdks/ruby"

  spec.files         = Dir["lib/**/*.rb", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]
end
