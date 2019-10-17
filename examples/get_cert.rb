require 'vcert'


CLOUDAPIKEY = ENV['CLOUDAPIKEY']
CLOUDURL = ENV['CLOUDURL']
CLOUDZONE = ENV['CLOUDZONE']
TPP_URL = ENV['TPPURL']
TPP_USER = ENV['TPPUSER']
TPP_PASSWORD = ENV['TPPPASSWORD']

conn = Vcert::Connection.new(url: CLOUDURL, cloud_token: CLOUDAPIKEY)

request = Vcert::Request.new common_name: "test.example.com", country: "US", province: "Utah", locality: "Salt Lake", organization: "Venafi"

certificate = conn.request_and_retrieve(request, CLOUDZONE, 600)


puts certificate.cert
puts certificate.chain
puts request.private_key

renew_request = Vcert::Request.new
renew_request.id = request.id
renew_cert_id = conn.renew(renew_request)
renew_request.id = renew_cert_id
renew_cert = conn.retrieve(renew_request)
puts "Renewed cert is:\n#{renew_cert.cert}"