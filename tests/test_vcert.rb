require 'minitest/autorun'
require 'vcert'
require 'openssl'

CLOUDAPIKEY = ENV['CLOUDAPIKEY']
CLOUDURL = ENV['CLOUDURL']
CLOUDZONE = ENV['CLOUDZONE']
TPPURL = ENV['TPPURL']
TPPUSER = ENV['TPPUSER']
TPPPASSWORD = ENV['TPPPASSWORD']
CSR_TEST = "-----BEGIN CERTIFICATE REQUEST-----
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
-----END CERTIFICATE REQUEST-----"
TEST_DOMAIN = ENV['TEST_DOMAIN']

def random_string(length)
  Array.new(length) { Array('a'..'z').sample }.join
end

def random_domain
  random_string(10) + "." + TEST_DOMAIN
end

class VcertTest < Minitest::Test
  def test_bad_request_cloud

  end

  def test_request_cloud
    conn = Vcert::Connection.new(url: CLOUDURL, cloud_token: CLOUDAPIKEY)
    LOG.info("Requesting cert with CN #{random_domain}")
    kt = Vcert::KeyType.new(type: "rsa", option: 4096)
    request = Vcert::Request.new(common_name: random_domain, country: "US", key_type: kt)
    zone_config = conn.read_zone_conf(CLOUDZONE)
    request.update_from_zone_config(zone_config)
    cert = conn.request_and_retrieve(request, CLOUDZONE, 300)
    LOG.info(("cert is:\n"+cert.cert))
    LOG.info(("pk is:\n"+cert.private_key))
  end

  def test_request_tpp
    conn = Vcert::Connection.new url: TPP_URL, user: TPP_USER, password: TPP_PASSWORD
    req = Vcert::Request.new common_name: 'test432432423.example.com'
    cert = conn.request_and_retrieve req, TPP_ZONE,600
    assert_match(/^-----BEGIN CERTIFICATE-----.*/, cert.cert)
    assert_match(/^-----BEGIN RSA PRIVATE KEY-----.*/, cert.private_key)
  end


  def test_read_zone_configuration_tpp
    conn = Vcert::Connection.new url: TPP_URL, user: TPP_USER, password: TPP_PASSWORD

    zone = conn.zone_configuration TPP_ZONE
  end

  def test_generate_csr
    req = Vcert::Request.new
    assert_raises do
      req.csr
    end
    req = Vcert::Request.new common_name: random_domain
    assert(req.csr.index("-----BEGIN CERTIFICATE REQUEST-----") == 0)
    req = Vcert::Request.new common_name: random_domain, csr: CSR_TEST
    assert_equal(req.csr, CSR_TEST)
    req = Vcert::Request.new common_name: random_domain, organization: "Venafi", organizational_unit: "Devops", country: "US", locality: "Salt Lake", province: "Utah"
    temp = req.csr
    assert_equal(temp, req.csr)
    req = Vcert::Request.new common_name: random_domain, key_type: "rsa", key_length: 4096
    csr = OpenSSL::X509::Request.new req.csr
    assert_equal(csr.public_key.n.num_bytes * 8, 4096)
    req = Vcert::Request.new common_name: random_domain, key_type: "ec"
    csr = OpenSSL::X509::Request.new req.csr
    assert_instance_of(OpenSSL::PKey::EC, csr.public_key)
  end
end
