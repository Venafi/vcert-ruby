require 'net/https'


class Vcert

  class Connection

    def initialize(url, token)
      @conn = CloudConnection.new url, token
    end

    def request(*args)
      @conn.request(*args)
    end
  end

end


require 'cloud/cloud'
require 'tpp/tpp'
