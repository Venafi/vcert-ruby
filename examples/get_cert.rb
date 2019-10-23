require 'vcert'


CLOUDAPIKEY = ENV['CLOUDAPIKEY']
CLOUDURL = ENV['CLOUDURL']
CLOUDZONE = ENV['CLOUDZONE']
TPP_URL = ENV['TPPURL']
TPP_USER = ENV['TPPUSER']
TPP_PASSWORD = ENV['TPPPASSWORD']

conn = Vcert::Connection.new(url: CLOUDURL, cloud_token: CLOUDAPIKEY)
# conn = Vcert::Connection.new url: TPPURL, user: TPPUSER, password: TPPPASSWORD, trust_bundle: TRUST_BUNDLE
zone = CLOUDZONE
# zone = TPPZONE

request = Vcert::Request.new common_name: "test.example.com", san_dns: ["ext-test.example.com"], country: "US", province: "Utah", locality: "Salt Lake", organization: "Venafi"

zone_config = conn.zone_configuration(zone)

request.update_from_zone_config(zone_config)

certificate = conn.request_and_retrieve(request, zone, timeout: 600)


puts certificate.cert
puts certificate.chain
puts request.private_key

renew_request = Vcert::Request.new
renew_request.id = request.id
renew_cert_id, renew_private_key = conn.renew(renew_request)
renew_request.id = renew_cert_id
renew_cert = conn.retrieve(renew_request)
puts "Renewed cert is:\n#{renew_cert.cert}"
puts "Renew pkey is:\n#{renew_private_key}"