require 'json'

class Vcert::CloudConnection
  def initialize(url, token)
    @url = url
    @token = token
  end


  def request(zone_tag, request)
    zone_id = get_zoneId_by_tag(zone_tag)
    data = post(URL_REQUEST, {:zoneId => zone_id, :certificateSigningRequest => request.csr})
    puts "Cert response:"
    puts JSON.pretty_generate(data)
    request.id = data['certificateRequests'][0]["id"]
    request
  end

  def retrieve(request)
    url = CERTIFICATE_RETRIEVE % request.id
    if request.chain_option == "first"
      url += "?chainOrder=#{CHAIN_OPTION_ROOT_FIRST}&format=PEM"
    elsif request.chain_option == "last"
      url += "?chainOrder=#{CHAIN_OPTION_ROOT_LAST}&format=PEM"
    else
      puts "chain option #{request.chain_option} is not valid"
      raise "Bad data"
    end
    data, response_code = get(url)
    if response_code == "200" or response_code == "409"
      return data
    else
      raise "Bad status #{response_code}"
    end
  end

  def ping
    true
  end

  private

  TOKEN_HEADER_NAME = "tppl-api-key"
  URL_REQUEST = "certificaterequests"
  URL_ZONE_BY_TAG = "zones/tag/"
  CERTIFICATE_RETRIEVE = URL_REQUEST + "/%s/certificate"
  CHAIN_OPTION_ROOT_FIRST = "ROOT_FIRST"
  CHAIN_OPTION_ROOT_LAST = "EE_FIRST"

  def get_zoneId_by_tag(tag)
    data, code = get(URL_ZONE_BY_TAG + tag)
    if code != "200"
      raise "Bad HTTP response from get zone"
    end
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
    if response.code != "200"
      raise "Bad HTTP response: #{response.body}"
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
    return data, response.code
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

end

