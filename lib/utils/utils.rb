def parse_pem_list(multiline)
  pems = []
  buf = ""
  current_string_is_pem = false
  multiline.each_line do |line|
    if line.match(/-----BEGIN [A-Z\ ]+-----/)
      current_string_is_pem = true
    end
    if current_string_is_pem
      buf = buf + line
    end
    if line.match(/-----END [A-Z\ ]+-----/)
      current_string_is_pem = false
      pems.push(buf)
      buf = ""
    end
  end
  pems
end

def parse_csr_fields(csr)
  LOG.info("#{Vcert::VCERT_PREFIX} Trying to parse CSR:\n#{csr}")
  csr_obj = OpenSSL::X509::Request.new(csr)
  result = Hash.new

  subject_array = csr_obj.subject.to_a
  subject_array.map do |x|
    if x[1] != ""
      result[x[0].to_sym] = x[1]
    end
  end

  attributes = csr_obj.attributes

  seq = nil
  values = nil

  if attributes
    attributes.each do |a|
      if a.oid == 'extReq'
        seq = a.value
        break
      end
    end
    # return nil if not seq
  end

  if seq
    seq.value.each do |v|
      v.each do |v|
        if v.value[0].value == 'subjectAltName'
          values = v.value[1].value
          break
        end
        break if values
      end
    end
    # return nil if not values
  end


  if values
    values = OpenSSL::ASN1.decode(values).value

    values.each do |v|
      case v.tag
      when 2
        result[:DNS] = v.value
      when 7
        case v.value.size
        when 4
          ip = v.value.unpack('C*').join('.')
        when 16
          ip = v.value.unpack('n*').map { |o| sprintf("%X", o) }.join(':')
        else
          STDERR.print "The encountered IP-address is neither IPv4 nor IPv6\n"
          next
        end
        result[:IP] = ip
      else
        STDERR.print "Uknown tag #{v.tag} -- I only know 2 (DNS) and 7 (IP)\n"
      end
    end
  end

  if csr_obj.public_key.instance_of? OpenSSL::PKey::RSA
    result[:key_type] = Vcert::KeyType.new "rsa", csr_obj.public_key.n.num_bits
  elsif csr_obj.public_key.instance_of? OpenSSL::PKey::EC
    # todo: implement
    raise "not implemented"
  else
    raise Vcert::VcertError
  end


  LOG.info("#{Vcert::VCERT_PREFIX} Parsed CSR fields:\n #{result.inspect}")
  return result
end

def parse_csr_fields_tpp(csr)
  LOG.info("#{Vcert::VCERT_PREFIX} Trying to parse CSR:\n#{csr}")
  csr_obj = OpenSSL::X509::Certificate.new(csr)
  result = Hash.new

  subject_array = csr_obj.subject.to_a
  subject_array.map do |x|
    result[x[0].to_sym] = x[1] unless x[1] == ''
  end

  LOG.info("#{Vcert::VCERT_PREFIX} Parsed CSR fields:\n #{result.inspect}")
  result
end

CLIENT_ID = 'vcert-sdk'.freeze
SCOPE = 'certificate:manage,revoke'.freeze

module Vcert
  class Authentication
    attr_accessor :access_token, :refresh_token, :user, :password, :token_expiration_date, :client_id, :scope

    def initialize (access_token: nil, refresh_token: nil, user: nil, password: nil, expiration_date: nil, client_id: CLIENT_ID, scope: SCOPE)
      @access_token = access_token
      @refresh_token = refresh_token
      @user = user
      @password = password
      @token_expiration_date = expiration_date
      @client_id = client_id
      @scope = scope
    end
  end

  class TokenInfo
    attr_reader :access_token, :refresh_token, :refresh_until, :expires, :identity, :scope, :token_type

    def initialize (access_token, expires, identity, refresh_token, refresh_until, scope, token_type)
      @access_token = access_token
      @refresh_token = refresh_token
      @refresh_until = refresh_until
      @expires = expires
      @identity = identity
      @scope = scope
      @token_type = token_type
    end
  end
end

