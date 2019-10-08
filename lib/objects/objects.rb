require 'openssl'
OpenSSL::PKey::EC.send(:alias_method, :private?, :private_key?)

module Vcert
  class Request
    attr_accessor :cert_id
    def initialize(common_name: nil, private_key: nil, key_type: "rsa", key_length: 2048, key_curve: "prime256v1",
                   organization: nil,  organizational_unit: nil, country: nil, province: nil, locality:nil, san_dns:nil,
                   cert_id: nil, csr: nil)
      @common_name = common_name
      @private_key = private_key
      #todo: parse private key and set public
      @key_type = key_type
      @key_length = key_length
      @key_curve = key_curve
      @organization = organization
      @organizational_unit = organizational_unit
      @country = country
      @province = province
      @locality = locality
      @san_dns = san_dns
      @cert_id = cert_id

      @csr = csr
    end

    def generate_csr
      if @private_key == nil
        generate_private_key
      end
      subject_attrs = [
          ['CN', @common_name]
      ]
      if @organization != nil
        subject_attrs.push(['O', @organization])
      end
      if @organizational_unit != nil
        subject_attrs.push(['OU', @organizational_unit])
      end
      if @country != nil
        subject_attrs.push(['C', @country])
      end
      if @province !=  nil
        subject_attrs.push(['ST', @province])
      end
      if @locality != nil
        subject_attrs.push(['L', @locality])
      end

      subject = OpenSSL::X509::Name.new subject_attrs
      csr = OpenSSL::X509::Request.new
      csr.version = 0
      csr.subject = subject
      csr.public_key = @public_key

      if @san_dns != nil
        san_list = @san_dns.map { |domain| "DNS:#{domain}" }
        extensions = [
            OpenSSL::X509::ExtensionFactory.new.create_extension('subjectAltName', san_list.join(','))
        ]
        attribute_values = OpenSSL::ASN1::Set [OpenSSL::ASN1::Sequence(extensions)]
        [
            OpenSSL::X509::Attribute.new('extReq', attribute_values),
            OpenSSL::X509::Attribute.new('msExtReq', attribute_values)
        ].each do |attribute|
          csr.add_attribute attribute
        end
      end
      csr.sign @private_key, OpenSSL::Digest::SHA256.new # todo: changable sign alg
      @csr = csr.to_pem
    end

    def csr
      if @csr == nil
        generate_csr
      end
      @csr
    end

    def private_key
      if @private_key == nil
        generate_private_key
      end
      @private_key.to_pem
    end

    private


    def generate_private_key
      if @key_type == "rsa"
        @private_key =  OpenSSL::PKey::RSA.new @key_length
        @public_key = @private_key.public_key
      elsif @key_type == "ec"
        @private_key, @public_key = OpenSSL::PKey::EC.new(@key_curve), OpenSSL::PKey::EC.new(@key_curve)
        @private_key.generate_key
        @public_key.public_key = @private_key.public_key
      end
      a = 1
    end

  end
end

