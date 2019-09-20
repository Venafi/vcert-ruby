

class Vcert::CloudConnection
  def initialize(url, token)
    @url = url
    @token = token
  end


  def request()
    post("/request", nil)
  end

  private

  def post(url, data)
    uri = URI.parse("https://venafi.com")
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    request.verify_mode = OpenSSL::SSL::VERIFY_NONE
    response = request.get("/")
    return response.body
  end

end

