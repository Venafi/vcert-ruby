require 'vcert'


CLOUD_TOKEN = ENV['CLOUDAPIKEY']
CLOUD_URL = ENV['CLOUD_URL']
CLOUD_ZONE = ENV['CLOUDZONE']
TPP_URL = ENV['TPPURL']
TPP_USER = ENV['TPPUSER']
TPP_PASSWORD = ENV['TPPPASSWORD']

conn = Vcert::Connection.new url: CLOUD_URL, cloud_token: CLOUD_TOKEN

request = Vcert::Request.new common_name: "test.example.com", country: "US", province: "Utah", locality: "Salt Lake", organization: "Venafi"

certificate = conn.request_and_retrieve(request, CLOUD_ZONE, 600)


puts certificate.cert
puts certificate.chain
puts request.private_key