require 'minitest/autorun'
require 'vcert'
require 'openssl'

CLOUD_TOKEN = "e6e67336-c669-41d0-9f7c-d17ae72b0e88"
CLOUD_URL = 'https://api.dev12.qa.venafi.io/v1/'
TPP_URL = 'https://ha-tpp1.sqlha.com:5008/vedsdk/'
TPP_USER = 'admin'
TPP_PASSWORD = 'newPassw0rd!'
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

def random_string(length)
    Array.new(length) { Array('a'..'z').sample }.join
end

def random_domain
    random_string(10) + ".example.com"
end

class VcertTest < Minitest::Test
  def test_request_cloud
    conn = Vcert::Connection.new CLOUD_URL, nil, nil, CLOUD_TOKEN
    assert_equal "123", conn.request("Default", Vcert::Request.new(common_name: random_domain , country: "US"))
  end

  def test_request_tpp
    conn = Vcert::Connection.new TPP_URL, TPP_USER, TPP_PASSWORD
    conn.request
    assert_equal "123", "123"
  end

  def test_generate_csr
    req = Vcert::Request.new
    assert_raises do
      req.csr
    end
    req = Vcert::Request.new common_name:  random_domain
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
