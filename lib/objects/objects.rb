require 'openssl'


module Vcert
  class Request
    def initialize(common_name: nil, private_key: nil, csr: nil)
      @common_name = common_name
      @private_key = private_key
      @csr = csr
    end

    def generate_csr

    end
    attr_reader :csr
    def csr?
      if @csr == nil
        generate_csr()
      end
      return @csr
    end
  end
end

