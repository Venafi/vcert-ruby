require 'json'
require 'date'
require 'base64'

class Vcert::TPPConnection
  def initialize(url, user, password)
    @url = normalize_url url
    @user = user
    @password = password
    @token = nil
  end

  def request(zone_tag, request)
    data = {:PolicyDN => policy_dn(zone_tag),
            :PKCS10 => request.csr,
            :ObjectName => request.friendly_name,
            :DisableAutomaticRenewal => "true"}
    code, response = post URL_CERTIFICATE_REQUESTS, data
    if code != 200
      raise "Bad server status code #{code}"
    end
    request.id = response['CertificateDN']
  end

  def retrieve(request)
    retrieve_request = {CertificateDN: request.id, Format: "base64", IncludeChain: 'true', RootFirstOrder: "false"}
    code, response = post URL_CERTIFICATE_RETRIEVE, retrieve_request
    if code != 200
      return nil
    end
    full_chain = Base64.decode64(response['CertificateData'])
    cert = parse_full_chain full_chain
    if cert.private_key == nil
      cert.private_key = request.private_key
    end
    cert
  end

  def policy(zone_tag)
    code, response = post URL_ZONE_CONFIG, {:PolicyDN => policy_dn(zone_tag)}
    if code != 200
      raise "Bad server status code #{code}"
    end

    def addStartEnd(s)
      unless s.index("^") == 0
        s = "^" + s
      end
      unless s.end_with?("$")
        s = s + "$"
      end
      s
    end

    def escape(value)
      if value.kind_of? Array
        return value.map { |v| addStartEnd(Regexp.escape(v)) }
      else
        return addStartEnd(regexp.QuoteMeta(value))
      end
    end
    policy = response["Policy"]
    s = policy["Subject"]
    if policy["WhitelistedDomains"]
      if policy["WildcardsAllowed"]
        subjectCNRegex = policy["WhitelistedDomains"].map { |d| addStartEnd('[\w-*]+' + Regexp.escape("." + d)) }
      else
        subjectCNRegex = policy["WhitelistedDomains"].map { |d| addStartEnd('[\w-]+' + Regexp.escape("." + d)) }
      end
    else
      subjectCNRegex = [ALL_ALLOWED_REGEX]
    end
    if s["OrganizationalUnit"]["Locked"]
      subjectOURegexes = escape(s["OrganizationalUnit"]["Values"])
    else
      subjectOURegexes = [ALL_ALLOWED_REGEX]
    end
    if s["Organization"]["Locked"]
      subjectORegexes = [escape(s["Organization"]["Value"])]
    else
      subjectORegexes = [ALL_ALLOWED_REGEX]
    end
    if s["City"]["Locked"]
      subjectLRegexes = [escape(s["City"]["Value"])]
    else
      subjectLRegexes = [ALL_ALLOWED_REGEX]
    end
    if s["State"]["Locked"]
      subjectSTRegexes = [escape(s["State"]["Value"])]
    else
      subjectSTRegexes = [ALL_ALLOWED_REGEX]
    end
    if s["Country"]["Locked"]
      subjectCRegexes = [escape(s["Country"]["Value"])]
    else
      subjectCRegexes = [ALL_ALLOWED_REGEX]
    end
    if policy["SubjAltNameDnsAllowed"]
      if policy["WhitelistedDomains"].length == 0
        dnsSanRegExs = [ALL_ALLOWED_REGEX]
      else
        dnsSanRegExs = policy["WhitelistedDomains"].map { |d| addStartEnd('[\w-]+' + Regexp.escape("." + d)) }
      end
    else
      dnsSanRegExs = []
    end
    if policy["SubjAltNameIpAllowed"]
      ipSanRegExs = [ALL_ALLOWED_REGEX] # todo: support
    else
      ipSanRegExs = []
    end
    if policy["SubjAltNameEmailAllowed"]
      emailSanRegExs = [ALL_ALLOWED_REGEX]  # todo: support
    else
      emailSanRegExs = []
    end
    if policy["SubjAltNameUriAllowed"]
      uriSanRegExs = [ALL_ALLOWED_REGEX]  # todo: support
    else
      uriSanRegExs = []
    end

    if policy["SubjAltNameUpnAllowed"]
      upnSanRegExs = [ALL_ALLOWED_REGEX] # todo: support
    else
      upnSanRegExs = []
    end
    unless policy["KeyPair"]["KeyAlgorithm"]["Locked"]
      key_types = [1024, 2048, 4096, 8192].map {|s| Vcert::KeyType.new("rsa", s) } + ["prime256v1"].map{|c| Vcert::KeyType.new("ec", c)} #todo: add all curves
    else
      if policy["KeyPair"]["KeyAlgorithm"]["Value"] == "RSA"
        if policy["KeyPair"]["KeySize"]["Locked"]
          key_types = [Vcert::KeyType.new("rsa", policy["KeyPair"]["KeySize"]["Value"])]
        else
          key_types = [1024, 2048, 4096, 8192].map {|s| Vcert::KeyType.new("rsa", s) }
        end
      elsif policy["KeyPair"]["KeyAlgorithm"]["Value"] == "EC"
        # todo: Write
      end
    end

    p = Vcert::Policy.new(policy_id: policy_dn(zone_tag), name: zone_tag, subject_cn_regexes: subjectCNRegex,
        subject_o_regexes: subjectORegexes, subject_ou_regexes: subjectOURegexes, subject_st_regexes: subjectSTRegexes,
                      subject_l_regexes: subjectLRegexes, subject_c_regexes:subjectCRegexes, san_regexes:dnsSanRegExs,
        key_types: key_types)
  end


  def zone_configuration(zone_tag)
    code, response = post URL_ZONE_CONFIG, {:PolicyDN => policy_dn(zone_tag)}
    if code != 200
      raise "Bad server status code #{code}"
    end
    s = response["Policy"]["Subject"]
    country = Vcert::CertField.new s["Country"]["Value"], locked: s["Country"]["Locked"]
    state = Vcert::CertField.new s["State"]["Value"], locked: s["State"]["Locked"]
    city = Vcert::CertField.new s["City"]["Value"], locked: s["City"]["Locked"]
    organization = Vcert::CertField.new s["Organization"]["Value"], locked: s["Organization"]["Locked"]
    organizational_unit = Vcert::CertField.new s["OrganizationalUnit"]["Values"], locked: s["OrganizationalUnit"]["Locked"]
    key_type = Vcert::KeyType.new response["Policy"]["KeyPair"]["KeyAlgorithm"]["Value"], key_length: response["Policy"]["KeyPair"]["KeySize"]["Value"]
    z = Vcert::ZoneConfiguration.new country, state, city, organization, organizational_unit, key_type
    z
  end

  private

  URL_AUTHORIZE = "authorize/"
  URL_CERTIFICATE_REQUESTS = "certificates/request"
  URL_ZONE_CONFIG = "certificates/checkpolicy"
  URL_CERTIFICATE_RETRIEVE = "certificates/retrieve"
  TOKEN_HEADER_NAME = "x-venafi-api-key"
  ALL_ALLOWED_REGEX = ".*"
  def auth
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.verify_mode = OpenSSL::SSL::VERIFY_NONE # todo: investigate verifying
    url = uri.path + URL_AUTHORIZE
    data = {:Username => @user, :Password => @password}
    encoded_data = JSON.generate(data)
    response = request.post(url, encoded_data, {"Content-Type" => "application/json"})
    data = JSON.parse(response.body)
    token = data['APIKey']
    valid_until = DateTime.strptime(data['ValidUntil'].gsub(/\D/, ''), '%Q')
    @token = token, valid_until
  end

  def post(url, data)
    if @token == nil || @token[1] < DateTime.now
      auth()
    end
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.verify_mode = OpenSSL::SSL::VERIFY_NONE # todo: investigate verifying
    url = uri.path + url
    encoded_data = JSON.generate(data)
    response = request.post(url, encoded_data, {TOKEN_HEADER_NAME => @token[0], "Content-Type" => "application/json"})
    data = JSON.parse(response.body)
    return response.code.to_i, data
  end

  def get
    if @token == nil || @token[1] < DateTime.now
      auth()
    end
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.verify_mode = OpenSSL::SSL::VERIFY_NONE # todo: investigate verifying
    url = uri.path + url
    response = request.get(url, {TOKEN_HEADER_NAME => @token[0]})
    data = JSON.parse(response.body)
    return response.code.to_i, data
  end

  def policy_dn(zone)
    if zone == nil || zone == ''
      raise "Empty zone"
    end
    if zone =~ /^\\\\VED\\\\Poplicy/
      return zone
    end
    if zone =~ /^\\\\/
      return '\\VED\\Policy' + zone
    else
      return '\\VED\\Policy\\' + zone
    end
  end

  def normalize_url(url)
    if url.index('http://') == 0
      url = "https://" + url[7..-1]
    elsif url.index('https://') != 0
      url = 'https://' + url
    end
    unless url.end_with?('/')
      url = url + '/'
    end
    unless url.end_with?('/vedsdk/')
      url = url + 'vedsdk/'
    end
    unless url =~ /^https:\/\/[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*\/vedsdk\/$/
      raise("bad TPP url")
    end
    url
  end

  def parse_full_chain(full_chain)
    pems = parse_pem_list(full_chain)
    Vcert::Certificate.new pems[0], pems[1..-1], nil # todo: parser
  end

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
end


