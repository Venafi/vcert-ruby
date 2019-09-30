require 'json'
require 'date'

class Vcert::TPPConnection
  def initialize(url, user, password)
    @url = url
    @user = user
    @password = password
    @token = nil
  end

  def request()
    post URL_CERTIFICATE_REQUESTS, {}
  end

  private
  URL_AUTHORIZE = "authorize/"
  URL_CERTIFICATE_REQUESTS = "certificates/request"
  TOKEN_HEADER_NAME = "x-venafi-api-key"
  def auth
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.verify_mode = OpenSSL::SSL::VERIFY_NONE  # todo: investigate verifying
    url = uri.path + URL_AUTHORIZE
    data = {:Username => @user, :Password => @password}
    encoded_data = JSON.generate(data)
    response = request.post(url ,encoded_data, {"Content-Type" => "application/json"})
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
    response = request.post(url, encoded_data,  {TOKEN_HEADER_NAME => @token[0], "Content-Type" => "application/json"})
    data = JSON.parse(response.body)
    return data
  end

  def get
    if @token == nil || @token[1] < DateTime.now
      auth()
    end
    uri = URI.parse(@url)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.verify_mode = OpenSSL::SSL::VERIFY_NONE  # todo: investigate verifying
    url = uri.path + url
    response = request.get(url,{TOKEN_HEADER_NAME => @token[0]})
    data = JSON.parse(response.body)
    return data
  end

end
