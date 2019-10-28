require 'vcert'


CLOUDAPIKEY = ENV['CLOUDAPIKEY']
CLOUDURL = ENV['CLOUDURL']
CLOUDZONE = ENV['CLOUDZONE']
TPPURL = ENV['TPPURL']
TPPUSER = ENV['TPPUSER']
TPPPASSWORD = ENV['TPPPASSWORD']
TRUST_BUNDLE = ENV['TRUST_BUNDLE']
TPPZONE = ENV['TPPZONE']
TPPZONE_RESTRICTED = ENV['TPPZONE_RESTRICTED']

if CLOUDAPIKEY != nil
  puts "Using Cloud connection"
  zone = CLOUDZONE
  conn = Vcert::Connection.new(url: CLOUDURL, cloud_token: CLOUDAPIKEY)
elsif TPPURL != nil && TPPPASSWORD != nil && TPPUSER != nil
  puts "Using Platform connection to #{TPPURL}"
  conn = Vcert::Connection.new url: TPPURL, user: TPPUSER, password: TPPPASSWORD, trust_bundle: TRUST_BUNDLE
  zone = TPPZONE
else
  puts "Using Fake connection"
  conn = Vcert::Connection.new(url: CLOUDURL, cloud_token: CLOUDAPIKEY, fake: true)
  zone = "fake"
end

request = Vcert::Request.new common_name: "test.example.com", san_dns: ["ext-test.example.com","ext2-test.example.com"], country: "US", province: "Utah", locality: "Salt Lake", organization: "Venafi"

# zone configuration contains default and strictly set values for request
zone_config = conn.zone_configuration(zone)

# you can update request with values from configuration
request.update_from_zone_config(zone_config)

certificate = conn.request_and_retrieve(request, zone, timeout: 600)

puts "cert is:\n#{certificate.cert}"
puts "chain is:\n#{certificate.chain}"
puts "pkey is:\n#{request.private_key}"

renew_request = Vcert::Request.new
renew_request.id = request.id
renew_cert_id, renew_private_key = conn.renew(renew_request)
renew_request.id = renew_cert_id
renew_cert = conn.retrieve_loop(renew_request)
puts "Renewed cert is:\n#{renew_cert.cert}"
puts "Renewed pkey is:\n#{renew_private_key}"

#Search by thumbprint
require "openssl"
renew_certificate_object = OpenSSL::X509::Certificate.new(renew_cert.cert)
thumbprint = OpenSSL::Digest::SHA1.new(renew_certificate_object.to_der).to_s
puts "Trying to renew by thumbprint #{thumbprint}"
thumbprint_renew_request = Vcert::Request.new
thumbprint_renew_request.thumbprint = thumbprint
thumbprint_renew_cert_id, thumbprint_renew_private_key = conn.renew(thumbprint_renew_request)
thumbprint_renew_request.id=thumbprint_renew_cert_id
thumbprint_renew_cert = conn.retrieve_loop(thumbprint_renew_request)
puts "thumbprint renewd cert is:\n" + thumbprint_renew_cert.cert
puts "thumbprint renewd key is:\n" + thumbprint_renew_private_key

#validating request
policy = conn.policy(TPPZONE_RESTRICTED)

request = Vcert::Request.new common_name: "test.example.com"
begin
  policy.check_request request
rescue Vcert::ValidationError
  puts "invalid request"
end

request = Vcert::Request.new csr: '-----BEGIN CERTIFICATE REQUEST-----
MIIC5TCCAc0CAQAwdzELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxFzAVBgNV
BAcMDlNhbHQgTGFrZSBDaXR5MQ8wDQYDVQQKDAZWZW5hZmkxFDASBgNVBAsMC0lu
dGVncmF0aW9uMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsowsaelHobgjtTdvPM/cbdxyb9HDxNA0+cMg
X0vXhrlb4gDa1ZpNGNh26uVBlxDIf63HaNEJyphrX48Lr3b/vViLW0/yVx/zqi0/
hwEnjlqMfKiBLq4pihxnCPVhUTXToFVBsYTURgu1CMS6LM0BBJK4sqf3cjLVyUH9
EKMz0HxbRJc9IcxirLLfDu580GiN8ggeRBKfZjnyZImbXEmjk9q0bZP8UySMi1fI
JpfeXyKHo/6HnB09qAtq71afzZOUABhZpXScmYNweDsQZTTW6hgf4WyxoywqdSiT
W5CmLdX/P4Vf4RYe0saDL1sHFrCiIibFBjxrtxTEXhfZbMSv2QIDAQABoCkwJwYJ
KoZIhvcNAQkOMRowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DANBgkqhkiG9w0B
AQsFAAOCAQEAQ++sKylm66h/iTXRVJxNiIdOIAsCD+Vdis091/EKJzVBF6bbHMo5
PUli1wm+PSaCbkiHClCziP9JKQkgeURLHNnvOidr3BX0n3AZ9i/s03yNlH3IiXSi
0QOc5Xl3REm9G341y40G8J3NjsJ2lZftjDb86LB6iOlkGmy7FHe/inkq4bA+Xlrp
AilzNOkXEeBwCT79bdpc3xh/hrjf9PeItLMpS7lVUUYQH18JK203BMGOE76EaELA
fk2X1wGedpdby5XRW0a7qozvwdBBTfI6/yMTP+iF5ghzvpCGtX2tYkyQ0I2GT/hV
YuWiOhL8NVOxPWFbiKWghQ2qH3hE0arsDA==
-----END CERTIFICATE REQUEST-----'

begin
  policy.check_request request
rescue Vcert::ValidationError
  puts "invalid request"
end