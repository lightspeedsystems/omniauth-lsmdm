# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "omniauth-lsmdm/version"

Gem::Specification.new do |s|
  s.name        = "omniauth-lsmdm"
  s.version     = Omniauth::Lsmdm::VERSION
  s.authors     = ["Andrew Hecht"]
  s.email       = ["andrewh@lightspeedsystems.com"]
  s.homepage    = "https://github.com/lightspeedsystems/omniauth-lsmdm"
  s.summary     = %q{OmniAuth strategy for My Big Campus}
  s.description = %q{OmniAuth strategy for My Big Campus}

  s.rubyforge_project = "omniauth-lsmdm"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_runtime_dependency 'omniauth-oauth', '~> 1.0'
  s.add_development_dependency 'rspec', '~> 2.7'
  s.add_development_dependency 'rack-test'
  s.add_development_dependency 'simplecov'
  s.add_development_dependency 'webmock'  
end
