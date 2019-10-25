require 'json'
require 'utils/utils'

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
        raise Vcert::ServerUnexpectedBehaviorError, "Certificate issue status is FAILED"
      when CERT_STATUS_ISSUED
        status, full_chain = get(URL_CERTIFICATE_RETRIEVE % request.id + "?chainOrder=#{CHAIN_OPTION_ROOT_LAST}&format=PEM")
        if status == 200
          cert = parse_full_chain full_chain
          if cert.private_key == nil
            cert.private_key = request.private_key
          end
          return cert
        else
          LOG.error("Cant issue certificate: #{full_chain}")
          raise Vcert::ServerUnexpectedBehaviorError, "Status #{status}"
        end
      else
        raise Vcert::ServerUnexpectedBehaviorError, "Unknown certificate status #{data['status']}"
      end
    end
  end

  def renew(request, generate_new_key: true)
    puts("Trying to renew certificate")
    if request.id == nil && request.thumbprint == nil
      raise Vcert::ClientBadDataError, "request id or certificate thumbprint must be specified for renewing certificate"
    end
    if request.thumbprint != nil
      manage_id = search_by_thumbprint(request.thumbprint)
    end
    if request.id != nil
      prev_request = get_cert_status(request)
      manage_id = prev_request[:manage_id]
      zone = prev_request[:zoneId]
    end
    if manage_id == nil
      raise Vcert::VcertError, "Can`t find manage_id"
    end

    status, data = get(URL_MANAGED_CERTIFICATE_BY_ID % manage_id)
    if status == 200
      request.id = data['latestCertificateRequestId']
    else
      raise Vcert::ServerUnexpectedBehaviorError, "Status #{status}"
    end

    if zone == nil
      prev_request = get_cert_status(request)
      zone = prev_request[:zoneId]
    end

    d = {existingManagedCertificateId: manage_id, zoneId: zone}
    if request.csr?
      d.merge!(certificateSigningRequest: request.csr)
      d.merge!(reuseCSR: false)
    elsif generate_new_key
      parsed_csr = parse_csr_fields(prev_request[:csr])
      renew_request = Vcert::Request.new(
          common_name: parsed_csr[:CN],
          san_dns: parsed_csr[:DNS],
          country: parsed_csr[:C],
          province: parsed_csr[:ST],
          locality: parsed_csr[:L],
          organization: parsed_csr[:O],
          organizational_unit: parsed_csr[:OU])
      d.merge!(certificateSigningRequest: renew_request.csr)
    else
      d.merge!(reuseCSR: true)
    end

    status, data = post(URL_CERTIFICATE_REQUESTS, data = d)
    if status == 201
      if generate_new_key
        return data['certificateRequests'][0]['id'], renew_request.private_key
      else
        return data['certificateRequests'][0]['id'], nil
      end

    else
      raise Vcert::ServerUnexpectedBehaviorError, "status: #{status} message: #{data}"
    end

  end

  def zone_configuration(tag)
    if tag.to_s.strip.empty?
      raise Vcert::ClientBadDataError, "Zone should not be empty"
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
    when 403
      raise Vcert::AuthenticationError
    else
      raise Vcert::ServerUnexpectedBehaviorError, "unexpected code #{response.code} for url #{url}. Message: #{response.body}"
    end
    case response.header['content-type']
    when "application/json"
      begin
        data = JSON.parse(response.body)
      rescue JSON::ParserError
        raise Vcert::ServerUnexpectedBehaviorError, "invalid json"
      end
    when "text/plain"
      data = response.body
    else
      raise Vcert::ServerUnexpectedBehaviorError, "unexpected content-type #{response.header['content-type']}"
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
    response = request.post(url, encoded_data, {TOKEN_HEADER_NAME => @token, "Content-Type" => "application/json", "Accept" => "application/json"})
    case response.code.to_i
    when 200, 201, 202, 409
      LOG.info(("HTTP status OK"))
    when 403
      raise Vcert::AuthenticationError
    else
      raise Vcert::ServerUnexpectedBehaviorError, "unexpected code #{response.code} for url #{url}. Message: #{response.body}"
    end
    data = JSON.parse(response.body)
    return response.code.to_i, data
  end

  def parse_full_chain(full_chain)
    pems = parse_pem_list(full_chain)
    Vcert::Certificate.new(
        cert: pems[0],
        chain: pems[1..-1]
    )
  end


  def get_policy_by_id(policy_id)
    status, data = get(URL_TEMPLATE_BY_ID % policy_id)
    if status != 200
      raise Vcert::ServerUnexpectedBehaviorError, "Invalid status during geting policy: %s for policy %s" % status, policy_id
    end
    parse_policy_responce_to_object(data)
  end

  def parse_policy_responce_to_object(d)
    key_types = []
    # TODO: need to change keytpyes to Vcert::KeyType objects
    d['keyTypes'].each { |kt| key_types.push(['keyType']) }
    Vcert::Policy.new(policy_id: d['id'],
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
  end

  def search_by_thumbprint(thumbprint)
    # thumbprint = re.sub(r'[^\dabcdefABCDEF]', "", thumbprint)
    thumbprint = thumbprint.upcase
    status, data = post(URL_CERTIFICATE_SEARCH, data = {"expression": {operands: [
        {field: "fingerprint", operator: "MATCH", value: thumbprint}]}})
    # TODO: check that data have valid certificate in it
    if status != 200
      raise Vcert::ServerUnexpectedBehaviorError, "Status: #{status}. Message: #{data.body.to_s}"
    end
    # TODO: check data
    manageId = data['certificates'][0]['managedCertificateId']
    LOG.info("Found certificate with manage id #{manageId}")
    return manageId
  end

  def get_cert_status(request)
    status, d = get(URL_CERTIFICATE_STATUS % request.id)
    if status == 200
      request_status = Hash.new
      request_status[:status] = d['status']
      request_status[:subject] = d['subjectDN'] or d['subjectCN'][0]
      request_status[:subject_alt_names] = d['subjectAlternativeNamesByType']
      request_status[:zoneId] = d['zoneId']
      request_status[:manage_id] = d['managedCertificateId']
      request_status[:csr] = d['certificateSigningRequest']
      request_status[:key_lenght] = d['keyLength']
      request_status[:key_type] = d['keyType']
      return request_status
    else
      raise Vcert::ServerUnexpectedBehaviorError, "status: #{status}"
    end
  end

end

