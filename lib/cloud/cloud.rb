require 'json'

class Vcert::CloudConnection
  def initialize(url, token)
    @url = url
    @token = token
  end


  def request(zone_tag, request)
    zone_id = get_zoneId_by_tag(zone_tag)
    data = post(CERTIFICATE_REQUESTS, {:zoneId => zone_id, :certificateSigningRequest => request.csr})
    puts "Cert response:"
    puts JSON.pretty_generate(data)
    request.id = data['certificateRequests'][0]["id"]
    request
  end

  def retrieve(request)
    puts("Getting certificate status for id %s" % request.id)
    status, data = get(CERTIFICATE_STATUS % request.id)
    if status == "200" or status == "409"
      if data['status'] == CERT_STATUS_PENDING or data['status'] == CERT_STATUS_REQUESTED
        puts("Certificate status is %s." % data['status'])
        return nil
      elsif data['status'] == CERT_STATUS_FAILED
        puts("Status is %s. Returning data for debug" % data['status'])
        raise "Certificate issue FAILED"
      elsif data['status'] == CERT_STATUS_ISSUED
        status, full_chain = get(CERTIFICATE_RETRIEVE % request.id + "?chainOrder=#{CHAIN_OPTION_ROOT_LAST}&format=PEM")
        if status == "200"
          cert = parse_full_chain full_chain
          if cert.private_key == nil
            cert.private_key = request.private_key
          end
          return cert
        else
          raise "Unexpected server behavior"
        end
      end
    end
  end

  def read_zone_conf(tag)
    _, data = get(URLS_ZONE_BY_TAG % tag)
    template_id = data['certificateIssuingTemplateId']
    _,data = get(URLS_TEMPLATE_BY_ID % template_id)
    puts data['keyTypes'].inspect
    puts data['keyTypes'][0]["keyLengths"][0].inspect
    kt = Vcert::KeyType.new type: data['keyTypes'][0]["keyType"], option: data['keyTypes'][0]["keyLengths"][0].to_i
    z = Vcert::ZoneConfiguration.new(
        country: Vcert::CertField.new(""),
        province: Vcert::CertField.new(""),
        locality: Vcert::CertField.new(""),
        organization: Vcert::CertField.new(""),
        organizational_unit: Vcert::CertField.new(""),
        key_type: kt,
    )
    return z
  end

  private

  TOKEN_HEADER_NAME = "tppl-api-key"
  URLS_ZONE_BY_TAG = "zones/tag/%s"
  URLS_TEMPLATE_BY_ID = "certificateissuingtemplates/%s"
  CERTIFICATE_REQUESTS = "certificaterequests"
  CERTIFICATE_STATUS = CERTIFICATE_REQUESTS + "/%s"
  CERTIFICATE_RETRIEVE = CERTIFICATE_REQUESTS + "/%s/certificate"
  CHAIN_OPTION_ROOT_FIRST = "ROOT_FIRST"
  CHAIN_OPTION_ROOT_LAST = "EE_FIRST"
  CERT_STATUS_REQUESTED = 'REQUESTED'
  CERT_STATUS_PENDING = 'PENDING'
  CERT_STATUS_FAILED = 'FAILED'
  CERT_STATUS_ISSUED = 'ISSUED'

  def get_zoneId_by_tag(tag)
    _, data = get(URLS_ZONE_BY_TAG % tag)
    data['id']
  end

  def get(url)
    #   TODO: find a way for normal http error handling
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.verify_mode = OpenSSL::SSL::VERIFY_NONE # todo: investigate verifying
    url = uri.path + "/" + url


    response = request.get(url, {TOKEN_HEADER_NAME => @token})
    case response.code
    when "200", "201", "202", "409"
      puts("HTTP status OK")
    else
      raise "Bad HTTP code #{response.code} for url #{url}. Message:\n #{response.body}"
    end
    if response.header['content-type'] == "application/json"
      begin
        data = JSON.parse(response.body)
      rescue JSON::ParserError
        raise "JSON parse error. Cant parse body response"
      end
    elsif response.header['content-type'] == "text/plain"
      data = response.body
    else
      raise "Can't process content-type #{response.header['content-type']}"
    end
    # rescue *ALL_NET_HTTP_ERRORS
    return response.code, data
    # end
  end

  def post(url, data)
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    # request.verify_mode = OpenSSL::SSL::VERIFY_NONE # todo: investigate verifying
    url = uri.path + "/" + url
    encoded_data = JSON.generate(data)
    response = request.post(url, encoded_data, {TOKEN_HEADER_NAME => @token, "Content-Type" => "application/json"})

    data = JSON.parse(response.body)
    data
  end

  def parse_full_chain(full_chain)
    pems = parse_pem_list(full_chain)
    cert = Vcert::Certificate.new(
        cert: pems[0],
        chain: pems[1..-1]
    )
    cert
  end

  def parse_pem_list(multiline)
    pems = []
    buf = ""
    current_string_is_pem = false
    multiline.each_line do |line|
      if line.match(/-----BEGIN [A-Z]+-----/)
        current_string_is_pem = true
      end
      if current_string_is_pem
        buf = buf + line
      end
      if line.match(/-----END [A-Z]+-----/)
        current_string_is_pem = false
        pems.push(buf)
        buf = ""
      end
    end
    pems
  end

  def get_policy_by_id(policy_id)
    status, data = get(URLS_TEMPLATE_BY_ID % policy_id)
    if status != "200"
      raise("Invalid status during geting policy: %s for policy %s" % status, policy_id)
    end
    return parse_policy_responce_to_object(data)
  end

  def parse_policy_responce_to_object(d)
    key_types = []
    d['keyTypes'].each { |kt| key_types.push(kt['keyType'])}
    policy = Vcert::Policy.new(policy_id: d['id'],
                               name: d['name'],
                               system_generated: d['systemGenerated'],
                               creation_date: d['creationDate'],
                               subject_cn_regexes: d['subjectCNRegexes'],
                               subject_o_regexes: d['subjectORegexes'],
                               subject_ou_regexes: d['subjectOURegexes'],
                               subject_st_regexes: d['subjectSTRegexes'],
                               subject_l_regexes: d['subjectLRegexes'],
                               subject_c_regexes: d['subjectCValues'],
                               san_regexes: d['sanRegexes'],
                               key_types: key_types)
    return policy
  end
end

