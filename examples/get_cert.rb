require 'vcert'


CLOUDAPIKEY = ENV['CLOUDAPIKEY']
CLOUDURL = ENV['CLOUDURL']
CLOUDZONE = ENV['CLOUDZONE']
TPPURL = ENV['TPPURL']
TPPUSER = ENV['TPPUSER']
TPPPASSWORD = ENV['TPPPASSWORD']
TRUST_BUNDLE = ENV['TRUST_BUNDLE']
TPPZONE = ENV['TPPZONE']

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

zone_config = conn.zone_configuration(zone)

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