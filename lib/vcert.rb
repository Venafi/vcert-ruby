require 'net/https'
require 'time'

module Vcert
  class Connection
    def initialize(url: nil, user: nil, password: nil, cloud_token: nil)
      if cloud_token != nil then
        @conn = CloudConnection.new url, cloud_token
      elsif user != nil && password != nil && url != nil then
        @conn = TPPConnection.new url, user, password
      else
        raise "Invalid credentials list" # todo: add typed exceptions
      end
    end

    def request(*args)
      @conn.request(*args)
    end

    def ping
      @conn.ping
    end

    def retrieve(*args)
      @conn.retrieve(*args)
    end

    def revoke(*args)
      @conn.revoke(*args)
    end

    def zone_configuration(*args)
      @conn.zone_configuration(*args)
    end

    def policy(*args)
      @conn.policy(*args)
    end

    def request_and_retrieve(req, zone, timeout)
      request zone, req
      t = Time.new() + timeout
      loop do
        if Time.new() > t
          #todo log
          break
        end
        certificate = retrieve(req)
        if certificate != nil
          return certificate
        end
        sleep 10
      end
      return nil
    end
  end
end


require 'cloud/cloud'
require 'tpp/tpp'
require 'objects/objects'