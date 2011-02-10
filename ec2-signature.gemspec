# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "ec2-signature/version"

Gem::Specification.new do |s|
  s.name        = "ec2-signature"
  s.version     = EC2::Signature::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["John Tran"]
  s.email       = ["jtran@attinteractive.com"]
  s.homepage    = "http://rubygems.org/gems/ec2-signature"
  s.summary     = %q{generate a signature to be posted to any EC2 compatible API}
  s.description = %q{AWS EC2 API generates signatures to authenticate.  This will generate one that is compatible even with Eucalyptus, OpenNebula & OpenStack.}

  s.rubyforge_project = "ec2-signature"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
end
