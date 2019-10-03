require 'json'


class Vcert::CloudConnection
  def initialize(url, token)
    @url = url
    @token = token
  end


  def request(zone_tag, request)
    zone_id = get_zoneId_by_tag(zone_tag)
    data = post(URL_REQUEST, {:zoneId => zone_id, :certificateSigningRequest => request.csr})
    request_id = data['certificateRequests'][0]["id"]
    return request_id
  end

  private
  TOKEN_HEADER_NAME = "tppl-api-key"
  URL_REQUEST =  "certificaterequests"
  URL_ZONE_BY_TAG = "zones/tag/"

  def get_zoneId_by_tag(tag)
    data = get(URL_ZONE_BY_TAG + tag)
    return data['id']
  end

  def get(url)
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.verify_mode = OpenSSL::SSL::VERIFY_NONE  # todo: investigate verifying
    url = uri.path + url
    response = request.get(url,{TOKEN_HEADER_NAME => @token})
    data = JSON.parse(response.body)
    return data
  end

  def post(url, data)
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.verify_mode = OpenSSL::SSL::VERIFY_NONE # todo: investigate verifying
    url = uri.path + url
    encoded_data = JSON.generate(data)
    response = request.post(url, encoded_data,  {TOKEN_HEADER_NAME => @token, "Content-Type" => "application/json"})
    data = JSON.parse(response.body)
    return data
  end

  def ping
    return true
  end
end

