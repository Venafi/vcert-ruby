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
    puts("Ping sucesfull. Requesting cert with CN #{random_domain}") if assert(conn.ping, "Ping should return true")
    request = Vcert::Request.new(common_name: random_domain, country: "US")
    cert = conn.request_and_retrieve(request, CLOUDZONE, 300)
    puts("cert is:\n"+cert.cert)
    puts("pk is:\n"+cert.private_key)
  end

  def test_request_tpp
    conn = Vcert::Connection.new url: TPP_URL, user: TPP_USER, password: TPP_PASSWORD
    req = Vcert::Request.new common_name: 'test432432423.example.com'
    cert = conn.request_and_retrieve req, TPP_ZONE,600

    puts cert.cert
    puts cert.private_key
    assert_equal "123", "123"
  end
end

class VcertLocalTest < Minitest::Test
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

  def test_match_regexp
    p = Vcert::Policy.new policy_id:nil, name:nil, system_generated:nil, creation_date:nil, subject_cn_regexes:nil, subject_o_regexes:nil,
        subject_ou_regexes:nil, subject_st_regexes:nil, subject_l_regexes:nil, subject_c_regexes:nil, san_regexes:nil,
        key_types:nil
    assert(p.send(:match_regexps?, "test", ["test", "ololo"]))
    assert(!p.send(:match_regexps?, "test", ["ololo"]))
    assert(!p.send(:match_regexps?, "test", []))
    assert(p.send(:match_regexps?, "test", [".*"]))
    assert(!p.send(:match_regexps?, "testtest", ["^test$"]))
    assert(!p.send(:match_regexps?, "", ["test"]))
    assert(p.send(:match_regexps?, "", ["test", ".*"]))
  end

  def test_key_pairs
    p = Vcert::Policy.new policy_id:nil, name:nil, system_generated:nil, creation_date:nil, subject_cn_regexes:nil, subject_o_regexes:nil,
                          subject_ou_regexes:nil, subject_st_regexes:nil, subject_l_regexes:nil, subject_c_regexes:nil, san_regexes:nil,
                          key_types:nil
    assert(!p.send(:is_key_type_is_valid?, Vcert::KeyType.new("rsa", 2048), []))
    assert(p.send(:is_key_type_is_valid?, Vcert::KeyType.new("rsa", 2048), [Vcert::KeyType.new("ec", "sec256k1"), Vcert::KeyType.new("rsa", 2048)]))
    assert(p.send(:is_key_type_is_valid?, Vcert::KeyType.new("rsa", 2048), [Vcert::KeyType.new("rsa", 2048)]))

  end
end
