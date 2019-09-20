require 'net/https'


module Vcert
  class CloudConnection
    def initialize(url, token)
      @url = url
      @token = token
    end

    def post
      uri = URI.parse("https://venafi.com/")
      request = Net::HTTP.new(uri.host, uri.port)
      request.use_ssl = true
      request.verify_mode = OpenSSL::SSL::VERIFY_NONE
      response = request.get("/")
      put response.body.size
    end

    def request()

    end
  end
end