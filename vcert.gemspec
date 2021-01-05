Gem::Specification.new do |s|
  s.name        = 'vcert'
  s.version     = '0.2.0'
  s.date        = '2021-01-05'
  s.summary     = "Library for Venafi products"
  s.description = "Ruby client for Venafi Cloud and Trust Protection Platform"
  s.authors     = ["Denis Subbotin", "Alexander Rykalin", "Russel Vela"]
  s.email       = 'opensource@venafi.com'
  s.files       = ["lib/vcert.rb", "lib/cloud/cloud.rb", "lib/tpp/tpp.rb", "lib/tpp/tpp_token.rb", "lib/objects/objects.rb", "lib/fake/fake.rb", "lib/utils/utils.rb"]
  s.homepage    =
    'https://rubygems.org/gems/vcert'
  s.license       = 'Apache-2.0'
end
