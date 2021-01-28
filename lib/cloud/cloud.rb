require 'json'
require 'utils/utils'
require 'addressable/uri'

class Vcert::CloudConnection
  CLOUD_PREFIX = '<Cloud>'.freeze

  def initialize(url, apikey)
    @url = if url.nil?
             'https://api.venafi.cloud'.freeze
           else
             url
           end
    @apikey = apikey
  end


  def request(zone_tag, request)
    zone_config = zone_configuration(zone_tag)
    _, data = post(URL_CERTIFICATE_REQUESTS, {:applicationId => zone_config.app_id,
                                              :certificateIssuingTemplateId=>zone_config.cit_id,
                                              :certificateSigningRequest => request.csr,
                                              :apiClientInformation => getApiClientInformation
    })
    LOG.debug("Raw response to certificate request:")
    LOG.debug(JSON.pretty_generate(data))
    request.id = data['certificateRequests'][0]["id"]
    request
  end

  def retrieve(request)
    LOG.info(("Getting certificate status for ID %s" % request.id))
    status, data = get(URL_CERTIFICATE_STATUS % request.id)
    if [200, 409].include? status
      case data['status']
      when CERT_STATUS_PENDING, CERT_STATUS_REQUESTED
        LOG.info(("Certificate status is: %s" % data['status']))
        return nil
      when CERT_STATUS_FAILED
        raise Vcert::ServerUnexpectedBehaviorError, "Certificate issue status is FAILED"
      when CERT_STATUS_ISSUED
        cert_arr = data["certificateIds"]
        status, full_chain = get(URL_CERTIFICATE_RETRIEVE % cert_arr[0] + "?chainOrder=#{CHAIN_OPTION_ROOT_LAST}&format=PEM")
        if status == 200
          cert = parse_full_chain full_chain
          if cert.private_key == nil
            cert.private_key = request.private_key
          end
          return cert
        else
          LOG.error("Can't issue certificate: #{full_chain}")
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
      raise Vcert::ClientBadDataError, "Either request ID or certificate thumbprint is required to renew the certificate"
    end
    if request.thumbprint != nil
      cert_id, request_id = search_by_thumbprint(request.thumbprint)
    end
    if request.id != nil
      prev_request = get_cert_status(request)
      request_id = request.id
      zone = prev_request[:zoneId]
    end
    if request_id == nil
      raise Vcert::VcertError, "Can't find the existing certificate request id"
    end

    status, data = get(URL_CERTIFICATE_STATUS % request_id)

    if status == 200
      request.id = data['id']
      cert_id = data['certificateIds'][0]
    else
      raise Vcert::ServerUnexpectedBehaviorError, "Status #{status}"
    end


    if prev_request == nil
      prev_request = get_cert_status(request)
    end


    d = {existingCertificateId: cert_id,
         applicationId: data["applicationId"],
         certificateIssuingTemplateId: data["certificateIssuingTemplateId"],
         apiClientInformation: getApiClientInformation

    }
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
      raise Vcert::VcertError, "This operation is not yet supported"
      #d.merge!(reuseCSR: true)
    end

    status, data = post(URL_CERTIFICATE_REQUESTS, data = d)
    if status == 201
      if generate_new_key
        return data['certificateRequests'][0]['id'], renew_request.private_key
      else
        return data['certificateRequests'][0]['id'], nil
      end

    else
      raise Vcert::ServerUnexpectedBehaviorError, "Status: #{status} Message: #{data}"
    end

  end

  def zone_configuration(tag)
    if tag.to_s.strip.empty?
      raise Vcert::ClientBadDataError, "Zone should not be empty"
    end
    LOG.info("Getting configuration for zone #{tag}")
    arr = tag.split("\\", 2)

    app_name = arr[0]
    cit_alias = arr[1]

    if app_name.to_s.strip.empty? || cit_alias.to_s.strip.empty?
      raise Vcert::ClientBadDataError, "The parameters: app_name, cit_alias or both are empty"
    end
    app_name =  Addressable::URI.encode_component(app_name, Addressable::URI::CharacterClasses::QUERY)
    cit_alias =  Addressable::URI.encode_component(cit_alias, Addressable::URI::CharacterClasses::QUERY)

    #get cit
    _, data = get(URL_CIT_BY_APP_NAME_CIT_ALIAS % [app_name, cit_alias])

    #get app info
    _, app = get(URL_APPLICATION_BY_NAME % app_name)

    kt = Vcert::KeyType.new data['keyTypes'][0]["keyType"], data['keyTypes'][0]["keyLengths"][0].to_i
    z = Vcert::ZoneConfiguration.new(
        country: Vcert::CertField.new(""),
        province: Vcert::CertField.new(""),
        locality: Vcert::CertField.new(""),
        organization: Vcert::CertField.new(""),
        organizational_unit: Vcert::CertField.new(""),
        key_type: Vcert::CertField.new(kt, locked: true),
    )
    z.app_id = app["id"]
    z.cit_id = data["id"]

    return z
  end

  def policy(zone_id)
    unless zone_id
      raise Vcert::ClientBadDataError, "Zone should be not nil"
    end
    arr = zone_id.split("\\", 2)

    app_name = arr[0]
    cit_alias = arr[1]

    if app_name.to_s.strip.empty? || cit_alias.to_s.strip.empty?
      raise Vcert::ClientBadDataError, "The parameters: app_name, cit_alias or both are empty"
    end

    app_name =  Addressable::URI.encode_component(app_name, Addressable::URI::CharacterClasses::QUERY)
    cit_alias =  Addressable::URI.encode_component(cit_alias, Addressable::URI::CharacterClasses::QUERY)
    status, data = get(URL_CIT_BY_APP_NAME_CIT_ALIAS % [app_name, cit_alias])
    puts data
    if status != 200
      raise Vcert::ServerUnexpectedBehaviorError, "Invalid status getting issuing template: %s for zone %s" % status, zone_id
    end
    parse_policy_responce_to_object(data)
  end

  private

  TOKEN_HEADER_NAME = "tppl-api-key"
  CHAIN_OPTION_ROOT_FIRST = "ROOT_FIRST"
  CHAIN_OPTION_ROOT_LAST = "EE_FIRST"
  CERT_STATUS_REQUESTED = 'REQUESTED'
  CERT_STATUS_PENDING = 'PENDING'
  CERT_STATUS_FAILED = 'FAILED'
  CERT_STATUS_ISSUED = 'ISSUED'
  URL_CIT_BY_APP_NAME_CIT_ALIAS = "outagedetection/v1/applications/%s/certificateissuingtemplates/%s"
  URL_APPLICATION_BY_NAME = "outagedetection/v1/applications/name/%s"
  URL_CERTIFICATE_REQUESTS = "outagedetection/v1/certificaterequests"
  URL_CERTIFICATE_STATUS = URL_CERTIFICATE_REQUESTS + "/%s"
  URL_CERTIFICATE_RETRIEVE = "outagedetection/v1/certificates/%s/contents"
  URL_CERTIFICATE_SEARCH = "outagedetection/v1/certificatesearch"


  def get(url)
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    url = uri.path + "/" + url


    LOG.info("#{CLOUD_PREFIX} GET #{url}")
    response = request.get(url, { TOKEN_HEADER_NAME => @apikey })
    case response.code.to_i
    when 200, 201, 202, 409
      LOG.info("#{CLOUD_PREFIX} GET HTTP status OK")
    when 403
      raise Vcert::AuthenticationError
    else
      raise Vcert::ServerUnexpectedBehaviorError, "Unexpected code #{response.code} for URL #{url}. Message: #{response.body}"
    end
    case response.header['content-type']
    when "application/json"
      begin
        data = JSON.parse(response.body)
      rescue JSON::ParserError
        raise Vcert::ServerUnexpectedBehaviorError, "Invalid JSON"
      end
    when "text/plain"
      data = response.body
    else
      raise Vcert::ServerUnexpectedBehaviorError, "Unexpected content-type #{response.header['content-type']}"
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
    LOG.info("#{CLOUD_PREFIX} POST #{url}")
    response = request.post(url, encoded_data, { TOKEN_HEADER_NAME => @apikey, "Content-Type" => "application/json", "Accept" => "application/json" })
    case response.code.to_i
    when 200, 201, 202, 409
      LOG.info("#{CLOUD_PREFIX} POST HTTP status OK")
    when 403
      raise Vcert::AuthenticationError
    else
      raise Vcert::ServerUnexpectedBehaviorError, "Unexpected code #{response.code} for URL #{url}. Message: #{response.body}"
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

  def parse_policy_responce_to_object(d)
    key_types = []
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
    certId = data['certificates'][0]['id']
    certReqId = data['certificates'][0]['certificateRequestId']
    LOG.info("Found existing certificate with ID #{certId}")
    return certId, certReqId
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

