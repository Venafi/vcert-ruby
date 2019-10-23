require "test/unit/assertions"
require 'minitest/autorun'
require 'vcert'
require 'openssl'

CLOUDAPIKEY = ENV['CLOUDAPIKEY']
CLOUDURL = ENV['CLOUDURL']
CLOUDZONE = ENV['CLOUDZONE']
TPPURL = ENV['TPPURL']
TPPUSER = ENV['TPPUSER']
TPPPASSWORD = ENV['TPPPASSWORD']
TPPZONE = ENV["TPPZONE"]
TRUST_BUNDLE = ENV["TRUST_BUNDLE"]
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
TEST_DOMAIN = "example.com"

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
    cn = random_domain
    conn = Vcert::Connection.new(url: CLOUDURL, cloud_token: CLOUDAPIKEY)
    LOG.info("Requesting cert with CN #{cn}")
    kt = Vcert::KeyType.new("rsa", 4096)
    request = Vcert::Request.new(common_name: cn, country: "US", key_type: kt, san_dns: ["ext-"+cn])
    zone_config = conn.zone_configuration(CLOUDZONE)
    request.update_from_zone_config(zone_config)
    cert = conn.request_and_retrieve(request, CLOUDZONE, timeout: 300)
    LOG.info(("cert is:\n" + cert.cert))
    LOG.info(("pk is:\n" + cert.private_key))

    certificate_object = OpenSSL::X509::Certificate.new(cert.cert)
    key_object = OpenSSL::PKey::RSA.new(cert.private_key)
    assert certificate_object.check_private_key(key_object)
    LOG.info("Subject is #{certificate_object.subject}")

    # Renew test
    renew_request = Vcert::Request.new
    renew_request.id = request.id
    renew_cert_id, renew_private_key = conn.renew(renew_request)
    renew_request.id = renew_cert_id
    renew_cert = conn.retrieve(renew_request)
    LOG.info(("renewd cert is:\n" + renew_cert.cert))
    LOG.info(("renewd cert key is:\n" + renew_private_key))
    renew_certificate_object = OpenSSL::X509::Certificate.new(renew_cert.cert)
    assert !renew_certificate_object.check_private_key(key_object), "Renewed cert signed by same key"
    renew_key_object = OpenSSL::PKey::RSA.new(renew_private_key)
    assert renew_certificate_object.check_private_key(renew_key_object), "Renewed cert signed by the wrong key"
    assert (certificate_object.serial != renew_certificate_object.serial), "Original cert sn and renew sn are equal"
    assert (certificate_object.subject.to_a.select{|name, _, _| name == 'CN' }.first[1] == renew_certificate_object.subject.to_a.select{|name, _, _| name == 'CN' }.first[1])

    #Search by thumbprint test, not working yet
    # thumbprint = OpenSSL::Digest::SHA1.new(renew_certificate_object.to_der).to_s
    # LOG.info("Trying to renew by thumbprint #{thumbprint}")
    # thumbprint_renew_request = Vcert::Request.new
    # thumbprint_renew_request.thumbprint = thumbprint
    # thumbprint_renew_cert_id = conn.renew(thumbprint_renew_request)
    # thumbprint_renew_cert = conn.retrieve(thumbprint_renew_cert_id)
    # LOG.info(("thumbprint renewd cert is:\n" + thumbprint_renew_cert.cert))
  end

  def test_request_tpp
    cn = random_domain
    conn = tpp_connection
    request = Vcert::Request.new common_name: cn
    zone_config = conn.zone_configuration(TPPZONE)
    request.update_from_zone_config(zone_config)
    cert = conn.request_and_retrieve request, TPPZONE, timeout: 600
    LOG.info(("cert is:\n" + cert.cert))
    LOG.info(("pk is:\n" + cert.private_key))

    LOG.info("csr is:\n#{request.csr}")
    #renew
    renew_request = Vcert::Request.new
    renew_request.id = request.id
    renew_cert_id, renew_private_key = conn.renew(renew_request)
    renew_request.id = renew_cert_id
    renew_cert = conn.retrieve_loop(renew_request)
    LOG.info(("renewd cert is:\n" + renew_cert.cert))
    LOG.info(("renewd cert key is:\n" + renew_private_key))
  end


  def test_zone_configuration_tpp
    conn = tpp_connection

    zone = conn.zone_configuration TPPZONE
  end

  def test_read_policy_tpp
    conn = tpp_connection

    policy = conn.policy TPPZONE
  end
end

def tpp_connection
  Vcert::Connection.new url: TPPURL, user: TPPUSER, password: TPPPASSWORD, trust_bundle: TRUST_BUNDLE
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
    req = Vcert::Request.new common_name: random_domain, key_type: Vcert::KeyType.new("rsa", 4096)
    csr = OpenSSL::X509::Request.new req.csr
    assert_equal(csr.public_key.n.num_bytes * 8, 4096)
    req = Vcert::Request.new common_name: random_domain, key_type: Vcert::KeyType.new("ecdsa", "prime256v1")
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
    assert(p.send(:is_key_type_is_valid?, Vcert::KeyType.new("rsa", 2048), [Vcert::KeyType.new("ec", "prime256v1"), Vcert::KeyType.new("rsa", 2048)]))
    assert(p.send(:is_key_type_is_valid?, Vcert::KeyType.new("rsa", 2048), [Vcert::KeyType.new("rsa", 2048)]))
  end


  def test_update_from_zone_config
    r = Vcert::Request.new common_name: "test.example.com", country: "US", locality: "New York"
    f = Vcert::CertField
    z = Vcert::ZoneConfiguration.new country: f.new("UK"),
                                     province: f.new("Utah"),
                                     locality: f.new("Salt Lake", locked: true),
                                     organization: f.new("Venafi", locked: true),
                                     organizational_unit: f.new(["Integsation", "Devops"]),
                                     key_type: f.new(Vcert::KeyType.new("ec", "prime256v1"))
    r.update_from_zone_config(z)
    assert_equal(r.country, "US")
    assert_equal(r.province, "Utah")
    assert_equal(r.locality, "Salt Lake")
    assert_equal(r.organization, "Venafi")
    assert_equal(r.organizational_unit, ["Integsation", "Devops"])
    assert_equal(r.key_type.type, "ecdsa")
    assert_equal(r.key_type.option, "prime256v1")
  end

  def test_check_with_policies
    r = Vcert::Request.new common_name: "test.example.com"
    p = new_policy_test_wrapper
    assert_nil(p.check_request(r))
    p = new_policy_test_wrapper(subject_cn_regexes: ["test.venafi.com"])
    assert_raises do
      p.check_request(r)
    end
    p = new_policy_test_wrapper(subject_cn_regexes: ["test.venafi.com"], key_types: [Vcert::KeyType.new("rsa", 2048), Vcert::KeyType.new("ecdsa", "secp521r1")])
    r = Vcert::Request.new common_name: "test.venafi.com", key_type: Vcert::KeyType.new("ecdsa", "prime256v1")
    assert_raises do
      p.check_request(r)
    end
    #todo: add more tests
  end

end

def new_policy_test_wrapper(policy_id: nil, name: "", system_generated: false, creation_date: nil,
                            subject_cn_regexes:[".*"], subject_o_regexes: [".*"], subject_ou_regexes:[".*"],
                            subject_st_regexes:[".*"], subject_l_regexes:[".*"], subject_c_regexes:[".*"],
                            san_regexes:[".*"], key_types: nil)
  if key_types == nil
    key_types = [1024, 2048, 4096, 8192].map {|s| Vcert::KeyType.new("rsa", s) } + Vcert::SUPPORTED_CURVES.map {|c| Vcert::KeyType.new("ecdsa", c) }
  end
  Vcert::Policy.new(policy_id: policy_id, name: name, system_generated: system_generated, creation_date: creation_date,
                    subject_cn_regexes: subject_cn_regexes, subject_o_regexes: subject_o_regexes,
                    subject_ou_regexes: subject_ou_regexes, subject_st_regexes: subject_st_regexes,
                    subject_l_regexes: subject_l_regexes, subject_c_regexes: subject_c_regexes, san_regexes: san_regexes,
                    key_types: key_types)
end