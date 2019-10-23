require 'openssl'
require 'base64'


ROOT_CA = "-----BEGIN CERTIFICATE-----
MIIDYDCCAkigAwIBAgIBATANBgkqhkiG9w0BAQsFADBBMRMwEQYKCZImiZPyLGQB
GRYDb3JnMRYwFAYKCZImiZPyLGQBGRYGVmVuYWZpMRIwEAYDVQQDDAlWZW5hZmkg
Q0EwHhcNMTkxMDIzMTIzNzExWhcNMjkxMDIwMTIzNzExWjBBMRMwEQYKCZImiZPy
LGQBGRYDb3JnMRYwFAYKCZImiZPyLGQBGRYGVmVuYWZpMRIwEAYDVQQDDAlWZW5h
ZmkgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4NfBNSVzOqj8A
E6+NSuEufK5EhgE/o8KPCTtM7qvMCa0X3P+T0I5IUDMXz5Yi/TXjhTANolYEz2RS
9u5Pdv5dvBCe1hwMhXdLlcxEhLtJrjnQvBUTqzuFUBausvRZvE3GwozoZncakEEP
OqTvGEpqjbnF1uiIJf944kjIq9oWnPudatOOlCFtpA1TG1mLJg8jcCrbeiXvRo9d
/dyg7B7URgKdxMukdjCkUMqUwArlu7mnv1kN6UdzhfFRCH0MBH4pisVze9XP/QrV
MJ+gMlultrpDFuMpiruJyPeapDnGloxtWKQ/aQHlnwwaX8fcaA3ADKUAFr66nFT2
14fgmByFAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEG
MB0GA1UdDgQWBBSFrxYL7Fd190DFUZFJ4ahzptV7tTAfBgNVHSMEGDAWgBSFrxYL
7Fd190DFUZFJ4ahzptV7tTANBgkqhkiG9w0BAQsFAAOCAQEAZsRtfC+4j6RWbWDZ
3eRabfY4Nl7z3q3hL2cYo98ZQVb5wssYwKPpX8/DFMnmgiObe0Na5zqaB9PxDBpZ
4wkRFpRfQ2oS13dzPMDdW0/IHhWfyWZiUqdpIacWIHvyuotZ/k3IZLT7zc9Lbs2p
FPmW5/Oe7lNRu3xgqaMuhRid8i426c+fR5YPf32umZtwRnB5hFFE9IlFBPpRl5Z7
GDJKJBgZi9+sk13a3CM8Zn0A9fiCaRASDPKRVhWPjDJwzLy44WF+1GiMZRCR79MX
8B/rNxkrKpWJmjkQj3jqmQOOnp7+QwdZ5OIV7NNlc/Kx2QDV9QV+hnRPetXmsVfy
y5KjSQ==
-----END CERTIFICATE-----
"
ROOT_KEY = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuDXwTUlczqo/ABOvjUrhLnyuRIYBP6PCjwk7TO6rzAmtF9z/
k9COSFAzF8+WIv0144UwDaJWBM9kUvbuT3b+XbwQntYcDIV3S5XMRIS7Sa450LwV
E6s7hVAWrrL0WbxNxsKM6GZ3GpBBDzqk7xhKao25xdboiCX/eOJIyKvaFpz7nWrT
jpQhbaQNUxtZiyYPI3Aq23ol70aPXf3coOwe1EYCncTLpHYwpFDKlMAK5bu5p79Z
DelHc4XxUQh9DAR+KYrFc3vVz/0K1TCfoDJbpba6QxbjKYq7icj3mqQ5xpaMbVik
P2kB5Z8MGl/H3GgNwAylABa+upxU9teH4JgchQIDAQABAoIBAEa/YIUuUdiFhiCv
btLjGUzTUdK7bKtWZ5irwPyxBYYdiT8K/5VzmdGoC5dvgIf7m8DAHE6ANG0wgaVj
dO9MEjFJ01BNhwRAFisPYx5Fo/COW2IRej7NmtR+h9ecnz//lBdsDNYM1F19XZ9N
tJ6nQ51cxSZ4fWIcxdtVfQKlDeN0y7ZanHsltv4cpCCuVaVk8uzI6O5E8dNbDmpR
Wotefps+9HHREa6uL39SbzU+S5SkdcVofs6/g/eL6RsP4D6VcF+qdBEQ38ffDaSZ
Q1hOwfTFf6Ahv4HhpCVC6vlIpXJi/RyUu6yqbmInvcXfGHvYoMYhud/lasYZDAm2
RdGB0gECgYEA7OHnaAqOaaYnE2rQkOAn3ZzA7VRhJgMvPgKUeQoUHDhXJOD/6wWD
1/wYd4BKiQyODi5cAlOkLvdrcRlnrGOKRiLgemyNrG2GzJTzgrkJc1IOpRnl2QKw
w1k0Xrv2qDpoebKMqhxjgEnYp+ddVB7kG561vl7JfhjQidrVqx6y/0UCgYEAxxPQ
M4myF4JKHpxU4+21JKxB3bTY7CWmKM1ZBon/ZFVKd8bsq7wt0tWP83oxWq5b11o+
AnWx4CsQQyl7EWanrDoPag2SjfI/q+AySq0VUNjcAsvPLfT2Q7WQQxEMQGoabZ7j
u8uxkNvZmDy5XGDjcZVdANq2kynC++v1AtwO3EECgYEAnmeeaCuO+kU6ojhuikLr
Rb3aIZqocFP21n/BK4O62PgwBiBT4qTIerlA30CyFx2HLSKBMqkeBK49cd8sPdI+
mBIgjJ1ky+ZeGxaMFGGKWUyJMIy18D1lWOyhIayOEAcm8CKe/+6F9zbqo7UK6wLR
RUsHe+tE0IblhRoKgijASAUCgYEAra7KkXxLhRklw0kPAwBLbqBeoqf6LSS3r5dg
WUUiLQ4Adzl1GGuH6w5plbmAv6Wo+NyBhzHZq0LG4GGbPlY6aRcKhbMrrm2wQSrL
lb0mALACWuonaefyxqXsI6cG8lffkM3zz87prwEv+RLZgRACvwDZ8Dng2cmwlIuK
6iDFUkECgYBL4U3E+trPuVEQm3Nj9nyIFV1efKDZ+uehPSvglYdO+ca7UgwA0btZ
iAAu3L3yP3TSJ6SbLV3hX1VoyyNQpUr+ODZo7VWf+MdZDh9XiiuLNqr5tx7yGhOb
1JXZ1QPAZeRvALui6fdj5yCHjTvayEL2nzPAFbgFrgVYRoF8L9O0gg==
-----END RSA PRIVATE KEY-----
"


class Vcert::FakeConnection
  def initialize()

  end

  def request(zone_tag, request)
    request.id = Base64.encode64(request.csr)
  end

  def retrieve(request)
    csrpem = Base64.decode64(request.id)
    csr =  OpenSSL::X509::Request.new(csrpem)
    root_ca = OpenSSL::X509::Certificate.new ROOT_CA
    root_key = OpenSSL::PKey::RSA.new ROOT_KEY
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.subject = csr.subject
    cert.issuer = root_ca.subject
    cert.not_before = Time.now
    cert.public_key = csr.public_key
    cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60
    # todo: add extensions
    cert.sign(root_key, OpenSSL::Digest::SHA256.new)
    Vcert::Certificate.new cert:cert.to_pem, chain: ROOT_CA, private_key: request.private_key

  end

  def policy(zone_tag)
        key_types = [1024, 2048, 4096, 8192].map {|s| Vcert::KeyType.new("rsa", s) } + Vcert::SUPPORTED_CURVES.map {|c| Vcert::KeyType.new("ecdsa", c) }
        Vcert::Policy.new(policy_id: zone_tag, name: zone_tag, system_generated: false, creation_date: nil,
                          subject_cn_regexes: [".*"], subject_o_regexes: [".*"],
                          subject_ou_regexes: [".*"], subject_st_regexes: [".*"],
                          subject_l_regexes: [".*"], subject_c_regexes: [".*"], san_regexes: [".*"],
                          key_types: key_types)
  end

  def zone_configuration(zone_tag)
    Vcert::ZoneConfiguration.new(
        country: Vcert::CertField.new("US"),
        province: Vcert::CertField.new("Utah"),
        locality: Vcert::CertField.new("Salt Lake City"),
        organization: Vcert::CertField.new("Venafi"),
        organizational_unit: Vcert::CertField.new("Devops"),
        key_type: Vcert::CertField.new(Vcert::KeyType.new("rsa", 2048), locked: true),
        )
  end
  def renew(request, generate_new_key: true)
    return request.id, nil
  end
end
