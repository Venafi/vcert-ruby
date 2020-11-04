require 'json'
require 'date'
require 'base64'
require 'utils/utils'

class Vcert::TokenConnection
  def initialize(url, access_token: nil, refresh_token: nil, user: nil, password: nil , trust_bundle: nil)
    @url = normalize_url url
    @auth = Authentication.new access_token, refresh_token, user, password
    @trust_bundle = trust_bundle
  end

  def request(zone_tag, request)
    data = { PolicyDN: policy_dn(zone_tag),
             PKCS10: request.csr,
             ObjectName: request.friendly_name,
             DisableAutomaticRenewal: 'true' }
    code, response = post URL_CERTIFICATE_REQUESTS, data
    raise Vcert::ServerUnexpectedBehaviorError, "Status  #{code}" if code != 200

    request.id = response['CertificateDN']
  end

  def retrieve(request)
    retrieve_request = { CertificateDN: request.id, Format: 'base64', IncludeChain: 'true', RootFirstOrder: 'false' }
    code, response = post URL_CERTIFICATE_RETRIEVE, retrieve_request
    return nil if code != 200

    full_chain = Base64.decode64(response['CertificateData'])
    cert = parse_full_chain full_chain
    cert.private_key = request.private_key if cert.private_key == nil
    cert
  end

  def policy(zone_tag)
    code, response = post URL_ZONE_CONFIG, { PolicyDN: policy_dn(zone_tag) }
    raise Vcert::ServerUnexpectedBehaviorError, "Status  #{code}" if code != 200

    parse_policy_response response, zone_tag
  end

  def zone_configuration(zone_tag)
    code, response = post URL_ZONE_CONFIG, { PolicyDN: policy_dn(zone_tag) }
    raise Vcert::ServerUnexpectedBehaviorError, "Status  #{code}" if code != 200

    parse_zone_configuration response
  end

  def renew(request, generate_new_key: true)
    if request.id.nil? && request.thumbprint.nil?
      raise('Either request ID or certificate thumbprint is required to renew the certificate')
    end

    request.id = search_by_thumbprint(request.thumbprint) if request.thumbprint != nil
    renew_req_data = { CertificateDN: request.id }
    if generate_new_key
      _, r = post(URL_SECRET_STORE_SEARCH, d = { Namespace: 'config', Owner: request.id, VaultType: 512 })
      vault_id = r['VaultIDs'][0]
      _, r = post(URL_SECRET_STORE_RETRIEVE, d = { VaultID: vault_id })
      csr_base64_data = r['Base64Data']
      csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\n#{csr_base64_data}\n-----END CERTIFICATE REQUEST-----\n"
      parsed_csr = parse_csr_fields(csr_pem)
      renew_request = Vcert::Request.new(
        common_name: parsed_csr.fetch(:CN, nil),
        san_dns: parsed_csr.fetch(:DNS, nil),
        country: parsed_csr.fetch(:C, nil),
        province: parsed_csr.fetch(:ST, nil),
        locality: parsed_csr.fetch(:L, nil),
        organization: parsed_csr.fetch(:O, nil),
        organizational_unit: parsed_csr.fetch(:OU, nil)
      )
      renew_req_data.merge!(PKCS10: renew_request.csr)
    end
    LOG.info('Trying to renew certificate %s' % request.id)
    _, d = post(URL_CERTIFICATE_RENEW, renew_req_data)
    if d.key?('Success')
      if generate_new_key
        return request.id, renew_request.private_key
      else
        return request.id, nil
      end
    else
      raise 'Certificate renew error'
    end

  end

  def get_access_token(authentication: nil)
    @auth = authentication unless authentication.nil?
    return refresh_access_token unless @auth.refresh_token.nil?

    return nil if @auth.user.nil? || @auth.password.nil?

    request_data = {
      username: @auth.user,
      password: @auth.password,
      client_id: @auth.client_id,
      scope: @auth.scope,
      state: ''
    }
    status, response = post(URL_AUTHORIZE_TOKEN, request_data, check_token: false, include_headers: false)
    raise Vcert::ServerUnexpectedBehaviorError, "Status  #{code}" if status != 200

    token_info = parse_access_token_data response
    update_authentication(token_info)
    token_info
  end

  def refresh_access_token
    request_data = {
      refresh_token: @auth.refresh_token,
      client_id: @auth.client_id
    }

    status, response = post(URL_REFRESH_TOKEN, request_data, check_token: false, include_headers: false)
    if status != 200
      raise Vcert::ServerUnexpectedBehaviorError, "Server returns #{code} status on refreshing access token"
    end

    token_info = parse_access_token_data(response)
    update_authentication(token_info)
    token_info
  end

  def revoke_access_token
    status, response = get(URL_REVOKE_TOKEN, check_token: false)
    if status != 200
      raise Vcert::ServerUnexpectedBehaviorError, "Server returns #{status} status on revoking access token"
    end

    response
  end

  private

  API_TOKEN_URL = 'vedauth/'.freeze
  API_BASE_URL = 'vedsdk/'.freeze

  URL_AUTHORIZE_TOKEN = "#{API_TOKEN_URL}authorize/oauth".freeze
  URL_REFRESH_TOKEN = "#{API_TOKEN_URL}authorize/token".freeze
  URL_REVOKE_TOKEN = "#{API_TOKEN_URL}revoke/token".freeze

  URL_AUTHORIZE = "#{API_BASE_URL}authorize/".freeze
  URL_CERTIFICATE_REQUESTS = "#{API_BASE_URL}certificates/request".freeze
  URL_ZONE_CONFIG = "#{API_BASE_URL}certificates/checkpolicy".freeze
  URL_CERTIFICATE_RETRIEVE = "#{API_BASE_URL}certificates/retrieve".freeze
  URL_CERTIFICATE_SEARCH = "#{API_BASE_URL}certificates/".freeze
  URL_CERTIFICATE_RENEW = "#{API_BASE_URL}certificates/renew".freeze
  URL_SECRET_STORE_SEARCH = "#{API_BASE_URL}SecretStore/LookupByOwner".freeze
  URL_SECRET_STORE_RETRIEVE = "#{API_BASE_URL}SecretStore/Retrieve".freeze
  HEADER_NAME_AUTHORIZATION = 'Authorization'.freeze
  ALL_ALLOWED_REGEX = '.*'.freeze

  def post(url, data, check_token: true, include_headers: true)
    validate_token if check_token

    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.ca_file = @trust_bundle unless @trust_bundle.nil?
    url = uri.path + url
    encoded_data = JSON.generate(data)
    headers = {
      'Content-Type': 'application/json'
    }
    headers.merge!(HEADER_NAME_AUTHORIZATION: build_authorization_header_value) if include_headers
    response = request.post(url, encoded_data, headers)
    data = JSON.parse(response.body)
    [response.code.to_i, data]
  end

  def get(url, check_token: true, include_headers: true)
    validate_token if check_token

    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.ca_file = @trust_bundle unless @trust_bundle.nil?

    url = uri.path + url

    headers = {}
    headers = { HEADER_NAME_AUTHORIZATION: build_authorization_header_value } if include_headers
    response = request.get(url, headers)
    # TODO: check valid json
    data = JSON.parse(response.body)
    [response.code.to_i, data]
  end

  def policy_dn(zone)
    raise Vcert::ClientBadDataError, 'Zone should not be empty' if zone.nil? || zone == ''
    return zone if zone =~ /^\\\\VED\\\\Policy/

    if zone =~ /^\\\\/
      "\\VED\\Policy#{zone}"
    else
      "\\VED\\Policy\\#{zone}"
    end
  end

  def normalize_url(url)
    if url.index('http://').zero?
      url = "https://#{url[7..-1]}"
    elsif url.index('https://') != 0
      url = "https://#{url}"
    end
    url += '/' unless url.end_with?('/')
    raise Vcert::ClientBadDataError, 'Invalid URL for TPP' unless url =~ %r{^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/$}

    url
  end

  def parse_full_chain(full_chain)
    pem_list = parse_pem_list(full_chain)
    Vcert::Certificate.new cert: pem_list[0], chain: pem_list[1..-1], private_key: nil
  end

  def search_by_thumbprint(thumbprint)
    # thumbprint = re.sub(r'[^\dabcdefABCDEF]', "", thumbprint)
    thumbprint = thumbprint.upcase
    status, data = get(URL_CERTIFICATE_SEARCH + "?Thumbprint=#{thumbprint}")
    # TODO: check that data have valid certificate in it
    raise Vcert::ServerUnexpectedBehaviorError, "Status: #{status}. Message:\n #{data.body.to_s}" if status != 200

    # TODO: check valid data
    data['Certificates'][0]['DN']
  end

  def parse_zone_configuration(data)
    s = data['Policy']['Subject']
    country = Vcert::CertField.new s['Country']['Value'], locked: s['Country']['Locked']
    state = Vcert::CertField.new s['State']['Value'], locked: s['State']['Locked']
    city = Vcert::CertField.new s['City']['Value'], locked: s['City']['Locked']
    organization = Vcert::CertField.new s['Organization']['Value'], locked: s['Organization']['Locked']
    organizational_unit = Vcert::CertField.new s['OrganizationalUnit']['Values'], locked: s['OrganizationalUnit']['Locked']
    key_type = Vcert::KeyType.new data['Policy']['KeyPair']['KeyAlgorithm']['Value'], data['Policy']['KeyPair']['KeySize']['Value']
    Vcert::ZoneConfiguration.new country: country, province: state, locality: city, organization: organization,
                                 organizational_unit: organizational_unit, key_type: Vcert::CertField.new(key_type)
  end

  def parse_policy_response(response, zone_tag)
    def addStartEnd(s)
      s = '^' + s unless s.index('^') == 0
      s = s + '$' unless s.end_with?('$')
      s
    end

    def escape(value)
      if value.kind_of? Array
        return value.map { |v| addStartEnd(Regexp.escape(v)) }
      else
        return addStartEnd(Regexp.escape(value))
      end
    end

    policy = response['Policy']
    s = policy['Subject']
    if policy['WhitelistedDomains'].empty?
      subjectCNRegex = [ALL_ALLOWED_REGEX]
    else
      if policy['WildcardsAllowed']
        subjectCNRegex = policy['WhitelistedDomains'].map { |d| addStartEnd('[\w\-*]+' + Regexp.escape('.' + d)) }
      else
        subjectCNRegex = policy['WhitelistedDomains'].map { |d| addStartEnd('[\w\-]+' + Regexp.escape('.' + d)) }
      end
    end
    if s['OrganizationalUnit']['Locked']
      subjectOURegexes = escape(s['OrganizationalUnit']['Values'])
    else
      subjectOURegexes = [ALL_ALLOWED_REGEX]
    end
    if s['Organization']['Locked']
      subjectORegexes = [escape(s['Organization']['Value'])]
    else
      subjectORegexes = [ALL_ALLOWED_REGEX]
    end
    if s['City']['Locked']
      subjectLRegexes = [escape(s['City']['Value'])]
    else
      subjectLRegexes = [ALL_ALLOWED_REGEX]
    end
    if s['State']['Locked']
      subjectSTRegexes = [escape(s['State']['Value'])]
    else
      subjectSTRegexes = [ALL_ALLOWED_REGEX]
    end
    if s['Country']['Locked']
      subjectCRegexes = [escape(s['Country']['Value'])]
    else
      subjectCRegexes = [ALL_ALLOWED_REGEX]
    end
    if policy['SubjAltNameDnsAllowed']
      if policy['WhitelistedDomains'].length == 0
        dnsSanRegExs = [ALL_ALLOWED_REGEX]
      else
        dnsSanRegExs = policy['WhitelistedDomains'].map { |d| addStartEnd('[\w-]+' + Regexp.escape('.' + d)) }
      end
    else
      dnsSanRegExs = []
    end
    if policy['SubjAltNameIpAllowed']
      ipSanRegExs = [ALL_ALLOWED_REGEX] # todo: support
    else
      ipSanRegExs = []
    end
    if policy['SubjAltNameEmailAllowed']
      emailSanRegExs = [ALL_ALLOWED_REGEX] # todo: support
    else
      emailSanRegExs = []
    end
    if policy['SubjAltNameUriAllowed']
      uriSanRegExs = [ALL_ALLOWED_REGEX] # todo: support
    else
      uriSanRegExs = []
    end

    if policy['SubjAltNameUpnAllowed']
      upnSanRegExs = [ALL_ALLOWED_REGEX] # todo: support
    else
      upnSanRegExs = []
    end
    unless policy['KeyPair']['KeyAlgorithm']['Locked']
      key_types = [1024, 2048, 4096, 8192].map { |s| Vcert::KeyType.new('rsa', s) } + Vcert::SUPPORTED_CURVES.map { |c| Vcert::KeyType.new('ecdsa', c) }
    else
      if policy['KeyPair']['KeyAlgorithm']['Value'] == 'RSA'
        if policy['KeyPair']['KeySize']['Locked']
          key_types = [Vcert::KeyType.new('rsa', policy['KeyPair']['KeySize']['Value'])]
        else
          key_types = [1024, 2048, 4096, 8192].map { |s| Vcert::KeyType.new('rsa', s) }
        end
      elsif policy['KeyPair']['KeyAlgorithm']['Value'] == 'EC'
        if policy['KeyPair']['EllipticCurve']['Locked']
          curve = { 'p224' => 'secp224r1', 'p256' => 'prime256v1', 'p521' => 'secp521r1' }[policy['KeyPair']['EllipticCurve']['Value'].downcase]
          key_types = [Vcert::KeyType.new('ecdsa', curve)]
        else
          key_types = Vcert::SUPPORTED_CURVES.map { |c| Vcert::KeyType.new('ecdsa', c) }
        end
      end
    end

    Vcert::Policy.new(policy_id: policy_dn(zone_tag), name: zone_tag, system_generated: false, creation_date: nil,
                      subject_cn_regexes: subjectCNRegex, subject_o_regexes: subjectORegexes,
                      subject_ou_regexes: subjectOURegexes, subject_st_regexes: subjectSTRegexes,
                      subject_l_regexes: subjectLRegexes, subject_c_regexes: subjectCRegexes, san_regexes: dnsSanRegExs,
                      key_types: key_types)
  end

  def parse_access_token_data(response_data)
    TokenInfo.new response_data['access_token'],
                  response_data['expires'],
                  response_data['identity'],
                  response_data['refresh_token'],
                  response_data['refresh_until'],
                  response_data['scope'],
                  response_data['token_type']
  end

  def update_authentication(token_info)
    return unless token_info.instance_of?(TokenInfo)

    @auth.access_token = token_info.access_token
    @auth.refresh_token = token_info.refresh_token
    @auth.token_expiration_data = token_info.expires
  end

  def validate_token
    if @auth.access_token.nil?
      get_access_token
    elsif !@auth.token_expiration_date.nil? && @auth.token_expiration_date <= DateTime.now && !@auth.refresh_token.nil?
      refresh_access_token
    else
      raise Vcert::AuthenticationError, 'Access Token expired. No refresh token provided.'
    end
  end

  def build_authorization_header_value
    return "Bearer #{@auth.access_token}" unless @auth.access_token.nil?
  end
end


