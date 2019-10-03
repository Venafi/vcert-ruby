require 'vcert'


CLOUD_TOKEN = ENV['CLOUDAPIKEY']
CLOUD_URL = ENV['CLOUD_URL']
CLOUD_ZONE = ENV['CLOUDZONE']
TPP_URL = ENV['TPPURL']
TPP_USER = ENV['TPPUSER']
TPP_PASSWORD = ENV['TPPPASSWORD']

conn = Vcert::Connection.new url: CLOUD_URL, cloud_token: CLOUD_TOKEN

request = Vcert::Request.new common_name: "test.example.com", country: "US", province: "Utah", locality: "Salt Lake", organization: "Venafi"

cert_id = conn.request(CLOUD_ZONE, request)
i = 0
loop do
  certificate = conn.retrieve(cert_id)
  if certificate != nil
    break
  end
  if i > 10
    raise "Too long waiting"
  end
  i +=1
  sleep 10
end


puts certificate.cert
puts certificate.chain
puts request.private_key