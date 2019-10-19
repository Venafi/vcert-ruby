require 'net/https'
require 'time'
require "logger"
LOG = Logger.new(STDOUT)

module Vcert
  class Connection
    def initialize(url: nil, user: nil, password: nil, cloud_token: nil, trust_bundle:nil)
      if cloud_token != nil then
        @conn = CloudConnection.new url, cloud_token
      elsif user != nil && password != nil && url != nil then
        @conn = TPPConnection.new url, user, password, trust_bundle:trust_bundle
      else
        raise "Invalid credentials list" # todo: add typed exceptions
      end
    end


    # @param [String] zone
    # @param [Request] request
    def request(zone, request)
      @conn.request(zone, request)
    end

    # @param [Request] request
    # @return [Certificate]
    def retrieve(request)
      @conn.retrieve(request)
    end

    def revoke(*args)
      @conn.revoke(*args)
    end

    # @param [String] zone
    # @return [ZoneConfiguration]
    def zone_configuration(zone)
      @conn.zone_configuration(zone)
    end

    # @param [String] zone
    # @return [Policy]
    def policy(zone)
      @conn.policy(zone)
    end

    def renew(*args)
      @conn.renew(*args)
    end

    # @param [Request] req
    # @param [String] zone
    # @param [Integer] timeout
    # @return [Certificate]
    def request_and_retrieve(req, zone, timeout)
      request zone, req
      t = Time.new() + timeout
      loop do
        if Time.new() > t
          LOG.info("Waiting certificate #{req.id}")
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