require 'json'
HTTP_ERRORS = [Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError, Net::HTTPNotFound]
ALL_NET_HTTP_ERRORS = [
    Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError,
    Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError, Net::HTTPNotFound
]
class Vcert::CloudConnection
  def initialize(url, token)
    @url = url
    @token = token
  end


  def request(zone_tag, request)
    zone_id = get_zoneId_by_tag(zone_tag)
    data = post(URL_REQUEST, {:zoneId => zone_id, :certificateSigningRequest => request.csr})
    request.id = data['certificateRequests'][0]["id"]
    request
  end

  def retrieve_cert(certificate_request)
    puts("Getting certificate status for id #{certificate_request.id}")

  end

  def ping
    true
  end

  private

  TOKEN_HEADER_NAME = "tppl-api-key"
  URL_REQUEST = "certificaterequests"
  URL_ZONE_BY_TAG = "zones/tag/"

  def get_zoneId_by_tag(tag)
    data = get(URL_ZONE_BY_TAG + tag)
    data['id']
  end

  def get(url)
    #   TODO: find a way for normal http error handling
    begin
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.verify_mode = OpenSSL::SSL::VERIFY_NONE # todo: investigate verifying
    url = uri.path + "/" + url


    response = request.get(url, {TOKEN_HEADER_NAME => @token})
    rescue *ALL_NET_HTTP_ERRORS => err
      raise "HTTP error!" + err.message
    end

    # HTTP_ERRORS.select { |e| raise "Bad response from GET: \n#{e.body}." if response == e }
    # raise "Bad response from GET: \n#{response.body}." if response == Timeout::Error || response == Errno::EINVAL || response == Errno::ECONNRESET || response == EOFError ||
    #     response == Net::HTTPBadResponse || response == Net::HTTPHeaderSyntaxError || response == Net::ProtocolError || response == Net::HTTPNotFound
    # if response == Net::HTTPNotFound
    #   raise "404!!!!"
    # end
    data = JSON.parse(response.body)
    # rescue *ALL_NET_HTTP_ERRORS
    data
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

