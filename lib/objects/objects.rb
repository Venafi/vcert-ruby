require 'openssl'
require "logger"
LOG = Logger.new(STDOUT)

OpenSSL::PKey::EC.send(:alias_method, :private?, :private_key?)

module Vcert
  SUPPORTED_CURVES = ["secp224r1", "prime256v1", "secp521r1"]
  class Request
    attr_accessor :id
    attr_reader :common_name, :country, :province, :locality, :organization, :organizational_unit, :san_dns,:key_type, :thumbprint

    def initialize(common_name: nil, private_key: nil, key_type: nil,
                   organization: nil, organizational_unit: nil, country: nil, province: nil, locality: nil, san_dns: nil,
                   friendly_name: nil, csr: nil)
      @common_name = common_name
      @private_key = private_key
      #todo: parse private key and set public
      if key_type != nil && !key_type.instance_of?(KeyType)
        raise Vcert::ClientBadDataError, "key_type bad type. should be Vcert::KeyType. for example KeyType('rsa', 2048)"
      end
      @key_type = key_type
      @organization = organization
      @organizational_unit = organizational_unit
      @country = country
      @province = province
      @locality = locality
      @san_dns = san_dns
      @friendly_name = friendly_name
      @id = nil
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
      if @province != nil
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
        #TODO: add check that san_dns is an array
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
      # TODO: find a way to pass CSR generation if renew is requested
      if @csr == nil
        generate_csr
      end
      @csr
    end

    def csr?
      @csr != nil
    end

    def private_key
      if @private_key == nil
        generate_private_key
      end
      @private_key.to_pem
    end

    def friendly_name
      if @friendly_name != nil
        return @friendly_name
      end
      @common_name
    end

    # @param [ZoneConfiguration] zone_config
    def update_from_zone_config(zone_config)
      if zone_config.country.locked || (!@country && !!zone_config.country.value)
        @country = zone_config.country.value
      end
      if zone_config.locality.locked || (!@locality && !!zone_config.locality.value)
        @locality = zone_config.locality.value
      end
      if zone_config.province.locked || (!@province && !!zone_config.province.value)
        @province = zone_config.province.value
      end
      if zone_config.organization.locked || (!@organization && !!zone_config.organization.value)
        @organization = zone_config.organization.value
      end
      if zone_config.organizational_unit.locked || (!@organizational_unit && !!zone_config.organizational_unit.value)
        @organizational_unit = zone_config.organizational_unit.value
      end
      if zone_config.key_type.locked || (@key_type == nil && zone_config.key_type.value != nil)
        @key_type = zone_config.key_type.value
      end
    end

    private


    def generate_private_key
      if @key_type == nil
        @key_type = DEFAULT_KEY_TYPE
      end
      if @key_type.type == "rsa"
        @private_key = OpenSSL::PKey::RSA.new @key_type.option
        @public_key = @private_key.public_key
      elsif @key_type.type == "ecdsa"
        @private_key, @public_key = OpenSSL::PKey::EC.new(@key_type.option), OpenSSL::PKey::EC.new(@key_type.option)
        @private_key.generate_key
        @public_key.public_key = @private_key.public_key
      end
    end
  end

  class Certificate
    attr_accessor :private_key
    attr_reader :cert, :chain

    def initialize(cert: nil, chain: nil, private_key: nil)
      @cert = cert
      @chain = chain
      @private_key = private_key
    end
  end

  class Policy
    attr_reader :policy_id, :name, :system_generated, :creation_date

    def initialize(policy_id:, name:, system_generated:, creation_date:, subject_cn_regexes:, subject_o_regexes:,
                   subject_ou_regexes:, subject_st_regexes:, subject_l_regexes:, subject_c_regexes:, san_regexes:,
                   key_types:)

      @policy_id = policy_id
      @name = name
      @system_generated = system_generated
      @creation_date = creation_date
      @subject_cn_regexes = subject_cn_regexes
      @subject_c_regexes = subject_c_regexes
      @subject_st_regexes = subject_st_regexes
      @subject_l_regexes = subject_l_regexes
      @subject_o_regexes = subject_o_regexes
      @subject_ou_regexes = subject_ou_regexes
      @san_regexes = san_regexes
      @key_types = key_types
    end

    # @param [Request] request
    def simple_check_request(request)
      unless component_is_valid?(request.common_name, @subject_cn_regexes)
        raise ValidationError, "Common name #{request.common_name} doesnt match #{@subject_cn_regexes}"
      end
      unless component_is_valid?(request.san_dns, @san_regexes, optional: true)
        raise ValidationError, "SANs #{request.san_dns} doesnt match #{ @san_regexes }"
      end

    end

    # @param [Request] request
    def check_request(request)
      simple_check_request(request)
      # subject
      unless component_is_valid?(request.country, @subject_c_regexes)
        raise ValidationError, "Country #{request.country} doesnt match #{@subject_c_regexes}"
      end
      unless component_is_valid?(request.province, @subject_st_regexes)
        raise ValidationError, "Province #{request.province} doesnt match #{@subject_st_regexes}"
      end
      unless component_is_valid?(request.locality, @subject_l_regexes)
        raise ValidationError, "Locality #{request.locality} doesnt match #{@subject_l_regexes}"
      end
      unless component_is_valid?(request.organization, @subject_o_regexes)
        raise ValidationError, "Organization #{request.organization} doesnt match #{@subject_o_regexes}"
      end
      unless component_is_valid?(request.organizational_unit, @subject_ou_regexes)
        raise ValidationError, "Organizational unit #{request.organizational_unit} doesnt match #{@subject_ou_regexes}"
      end
      #todo: add uri, upn, ip, email
      unless is_key_type_is_valid?(request.key_type, @key_types)
        raise ValidationError, "Key Type #{request.key_type} doesnt match allowed #{@key_types}"
      end
      # todo: (!important!) parse csr if it alredy generated (!important!)
    end

    private

    def is_key_type_is_valid?(key_type, allowed_key_types)
      if key_type == nil
        key_type = DEFAULT_KEY_TYPE
      end
      for i in 0 ... allowed_key_types.length
        if allowed_key_types[i] == key_type
          return true
        end
      end
      false
    end

    def component_is_valid?(component, regexps, optional:false)
      if component == nil
        component = []
      end
      unless component.instance_of? Array
        component = [component]
      end
      if component.length == 0 && optional
        return true
      end
      if component.length == 0
        component = [""]
      end
      for i in 0 ... component.length
        unless match_regexps?(component[i], regexps)
          return false
        end
      end
      true
    end

    def match_regexps?(s, regexps)
      for i in 0 ... regexps.length
        if Regexp.new(regexps[i]).match(s)
          return true
        end
      end
      false
    end
  end

  class ZoneConfiguration
    attr_reader :country, :province, :locality, :organization, :organizational_unit, :key_type

    # @param [CertField] country
    # @param [CertField] province
    # @param [CertField] locality
    # @param [CertField] organization
    # @param [CertField] organizational_unit
    # @param [CertField] key_type
    def initialize(country:, province:, locality:, organization:, organizational_unit:, key_type:)
      @country = country
      @province = province
      @locality = locality
      @organization = organization
      @organizational_unit = organizational_unit
      @key_type = key_type
    end
  end

  class CertField
    attr_reader :value, :locked

    def initialize(value, locked: false)
      @value = value
      @locked = locked
    end
  end

  class KeyType
    attr_reader :type, :option

    def initialize(type, option)
      @type = {"rsa" => "rsa", "ec" => "ecdsa", "ecdsa" => "ecdsa"}[type.downcase]
      if @type == nil
        raise Vcert::VcertError, "bad key type"
      end
      if @type == "rsa"
        unless  [512, 1024, 2048, 3072, 4096, 8192].include?(option)
          raise  Vcert::VcertError,"bad option for rsa key: #{option}. should be one from list 512, 1024, 2048, 3072, 4096, 8192"
        end
      else
        unless SUPPORTED_CURVES.include?(option)
          raise Vcert::VcertError, "bad option for ec key: #{option}. should be one from list #{ SUPPORTED_CURVES}"
        end
      end
      @option = option
    end
    def ==(other)
      unless other.instance_of? KeyType
        return false
      end
      self.type == other.type && self.option == other.option
    end
  end
  DEFAULT_KEY_TYPE = KeyType.new("rsa", 2048)
end

