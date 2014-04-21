# -*- encoding: utf-8 -*-
require File.expand_path('../lib/fog/bouncer/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Dylan Egan"]
  gem.email         = ["dylanegan@gmail.com"]
  gem.description   = %q{A simple way to define and manage security groups for AWS with the backing support of fog.}
  gem.summary       = %q{A manage security.}
  gem.homepage      = "https://github.com/dylanegan/fog-bouncer"

  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.name          = "fog-bouncer"
  gem.require_paths = ["lib"]
  gem.version       = Fog::Bouncer::VERSION

  gem.add_dependency "clamp", "~> 0.5.0"
  gem.add_dependency "clarence", "1987.0.0"
  gem.add_dependency "fog", "~> 1.2"
  gem.add_dependency "ipaddress", "~> 0.8.0"
  gem.add_dependency "jruby-openssl", "~> 0.7.6" if RUBY_PLATFORM == "java"
  gem.add_dependency "rake", "~> 0.9.0"
  gem.add_dependency "scrolls", "~> 0.2.1"

  gem.add_development_dependency "minitest"
end
