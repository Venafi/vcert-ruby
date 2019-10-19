require 'json'

class CertificateStatusResponse

  attr_reader :status, :subject, :zoneId, :manage_id

  def initialize(d)
    @status = d['status']
    @subject = d['subjectDN'] or d['subjectCN'][0]
    @zoneId = d['zoneId']
    @manage_id = d['managedCertificateId']
  end
end

class Vcert::CloudConnection
  def initialize(url, token)
    @url = url
    @token = token
  end


  def request(zone_tag, request)
    zone_id = get_zoneId_by_tag(zone_tag)
    _, data = post(URL_CERTIFICATE_REQUESTS, {:zoneId => zone_id, :certificateSigningRequest => request.csr})
    LOG.info("Cert response:")
    LOG.info(JSON.pretty_generate(data))
    request.id = data['certificateRequests'][0]["id"]
    request
  end

  def retrieve(request)
    LOG.info(("Getting certificate status for id %s" % request.id))
    status, data = get(URL_CERTIFICATE_STATUS % request.id)
    if [200, 409].include? status
      case data['status']
      when CERT_STATUS_PENDING, CERT_STATUS_REQUESTED
        LOG.info(("Certificate status is %s." % data['status']))
        return nil
      when CERT_STATUS_FAILED
        LOG.info(("Status is %s. Returning data for debug" % data['status']))
        raise "Certificate issue FAILED"
      when CERT_STATUS_ISSUED
        status, full_chain = get(URL_CERTIFICATE_RETRIEVE % request.id + "?chainOrder=#{CHAIN_OPTION_ROOT_LAST}&format=PEM")
        if status == 200
          cert = parse_full_chain full_chain
          if cert.private_key == nil
            cert.private_key = request.private_key
          end
          return cert
        else
          raise "Unexpected server behavior"
        end
      else
        raise "Unexpected server behavior"
      end
    end
  end

  def renew(request)
    puts("Trying to renew certificate")
    if request.id == nil && request.thumbprint == nil
      raise("request id or certificate thumbprint must be specified for renewing certificate")
    end
    if request.thumbprint != nil
      manage_id = search_by_thumbprint(request.thumbprint)
    end
    if request.id != nil
      prev_request = get_cert_status(request)
      manage_id = prev_request.manage_id
      zone = prev_request.zoneId
    end
    if manage_id == nil
      raise "Can`t find manage_id"
    end

    status, data = get(URL_MANAGED_CERTIFICATE_BY_ID % manage_id)
    if status == 200
      request.id = data['latestCertificateRequestId']
    else
      raise "Server Unexpted Behavior"
    end

    if zone == nil
      prev_request = get_cert_status(request)
      zone = prev_request.zoneId
    end

    d = {existingManagedCertificateId: manage_id, zoneId: zone}
    if request.csr?
      d.merge!(certificateSigningRequest: request.csr)
      d.merge!(reuseCSR: false)
    else
      d.merge!(reuseCSR: true)
    end

    status, data = post(URL_CERTIFICATE_REQUESTS, data = d)
    if status == 201
      return data['certificateRequests'][0]['id']
    else
      raise "server unexpected status: #{status}\n message: #{data}"
    end

  end

  def zone_configuration(tag)
    if tag.to_s.strip.empty?
      raise "Zone should not be empty"
    end
    LOG.info("Getting configuration for zone #{tag}")
    _, data = get(URL_ZONE_BY_TAG % tag)
    template_id = data['certificateIssuingTemplateId']
    _, data = get(URL_TEMPLATE_BY_ID % template_id)
    kt = Vcert::KeyType.new data['keyTypes'][0]["keyType"], data['keyTypes'][0]["keyLengths"][0].to_i
    z = Vcert::ZoneConfiguration.new(
        country: Vcert::CertField.new(""),
        province: Vcert::CertField.new(""),
        locality: Vcert::CertField.new(""),
        organization: Vcert::CertField.new(""),
        organizational_unit: Vcert::CertField.new(""),
        key_type: Vcert::CertField.new(kt, locked: true),
    )
    return z
  end

  private

  TOKEN_HEADER_NAME = "tppl-api-key"
  CHAIN_OPTION_ROOT_FIRST = "ROOT_FIRST"
  CHAIN_OPTION_ROOT_LAST = "EE_FIRST"
  CERT_STATUS_REQUESTED = 'REQUESTED'
  CERT_STATUS_PENDING = 'PENDING'
  CERT_STATUS_FAILED = 'FAILED'
  CERT_STATUS_ISSUED = 'ISSUED'
  URL_ZONE_BY_TAG = "zones/tag/%s"
  URL_TEMPLATE_BY_ID = "certificateissuingtemplates/%s"
  URL_CERTIFICATE_REQUESTS = "certificaterequests"
  URL_CERTIFICATE_STATUS = URL_CERTIFICATE_REQUESTS + "/%s"
  URL_CERTIFICATE_RETRIEVE = URL_CERTIFICATE_REQUESTS + "/%s/certificate"
  URL_CERTIFICATE_SEARCH = "certificatesearch"
  URL_MANAGED_CERTIFICATES = "managedcertificates"
  URL_MANAGED_CERTIFICATE_BY_ID = URL_MANAGED_CERTIFICATES + "/%s"

  def get_zoneId_by_tag(tag)
    _, data = get(URL_ZONE_BY_TAG % tag)
    data['id']
  end

  def get(url)
    #   TODO: find a way for normal http error handling
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    url = uri.path + "/" + url


    response = request.get(url, {TOKEN_HEADER_NAME => @token})
    case response.code.to_i
    when 200, 201, 202, 409
      LOG.info(("HTTP status OK"))
    else
      raise "Bad HTTP code #{response.code} for url #{url}. Message:\n #{response.body}"
    end
    case response.header['content-type']
    when "application/json"
      begin
        data = JSON.parse(response.body)
      rescue JSON::ParserError
        raise "JSON parse error. Cant parse body response"
      end
    when "text/plain"
      data = response.body
    else
      raise "Can't process content-type #{response.header['content-type']}"
    end
    # rescue *ALL_NET_HTTP_ERRORS
    return response.code.to_i, data
    # end
  end

  def post(url, data)
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    url = uri.path + "/" + url
    encoded_data = JSON.generate(data)
    response = request.post(url, encoded_data, {TOKEN_HEADER_NAME => @token, "Content-Type" => "application/json"})
    case response.code.to_i
    when 200, 201, 202, 409
      LOG.info(("HTTP status OK"))
    else
      raise "Bad HTTP code #{response.code} for url #{url}. Message:\n #{response.body}"
    end
    data = JSON.parse(response.body)
    return response.code.to_i, data
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
    status, data = get(URL_TEMPLATE_BY_ID % policy_id)
    if status != 200
      raise("Invalid status during geting policy: %s for policy %s" % status, policy_id)
    end
    return parse_policy_responce_to_object(data)
  end

  def parse_policy_responce_to_object(d)
    key_types = []
    # TODO: need to change keytpyes to Vcert::KeyType objects
    d['keyTypes'].each { |kt| key_types.push(['keyType']) }
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

  def search_by_thumbprint(thumbprint)
    # thumbprint = re.sub(r'[^\dabcdefABCDEF]', "", thumbprint)
    thumbprint = thumbprint.upcase
    status, data = post(URL_CERTIFICATE_SEARCH, data={expression: {operands: [
        {field: "fingerprint", operator: "MATCH", value: thumbprint}]}})
    # TODO: check that data have valid certificate in it
    if status != 200
      raise "Unexpected status code on Venafi Cloud certificate search. Status: #{status}. Message:\n #{data.body.to_s}"
    end
    return data['certificates'][0]
  end

  def get_cert_status(request)
    status, data = get(URL_CERTIFICATE_STATUS % request.id)
    if status == 200
      request_status = CertificateStatusResponse.new(data)
      return request_status
    else
      raise "Server unexpted behavior"
    end
  end

end

