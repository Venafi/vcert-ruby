Gem::Specification.new do |s|
  s.name        = 'vcert'
  s.version     = '0.1.1'
  s.date        = '2019-09-18'
  s.summary     = "Library for Venafi products"
  s.description = "Ruby client for Venafi Cloud and Trust Protection Platform"
  s.authors     = ["Denis Subbotin", "Alexander Rykalin"]
  s.email       = 'opensource@venafi.com'
  s.files       = ["lib/vcert.rb", "lib/cloud/cloud.rb", "lib/tpp/tpp.rb", "lib/tpp/tpp_token.rb", "lib/objects/objects.rb", "lib/fake/fake.rb", "lib/utils/utils.rb"]
  s.homepage    =
    'https://rubygems.org/gems/vcert'
  s.license       = 'Apache-2.0'
end