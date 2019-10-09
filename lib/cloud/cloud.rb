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
    sleep(5)
    status, data = get(CERTIFICATE_STATUS % request.id)
    if status == "200" or status == "409"
      if data['status'] == CERT_STATUS_PENDING or data['status'] == CERT_STATUS_REQUESTED
        puts("Certificate status is %s." % data['status'])
        return nil
      elsif data['status'] == CERT_STATUS_FAILED
        puts("Status is %s. Returning data for debug" % data['status'])
        raise "Certificate issue FAILED"
      elsif data['status'] == CERT_STATUS_ISSUED
        sleep(1)
        # status, data = get(CERTIFICATE_RETRIEVE % request.id + "?chainOrder=last&format=PEM")
        status, full_chain = get(CERTIFICATE_RETRIEVE % request.id)
        if status == "200"
          cert = parse_full_chain full_chain
          if cert.private_key == nil
            cert.private_key = request.private_key
          end
        else
          raise "Unexpected server behavior"
        end
      end
    end
  end

  def ping
    true
  end

  private

  TOKEN_HEADER_NAME = "tppl-api-key"
  URL_ZONE_BY_TAG = "zones/tag/"
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
    status, data = get(URL_ZONE_BY_TAG + tag)
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
    Vcert::Certificate.new  full_chain, '', nil # todo: parser
  end
end

