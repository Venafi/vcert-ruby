require 'net/https'
require 'time'

TIMEOUT = 420

module Vcert
  class VcertError < StandardError ; end
  class AuthenticationError < VcertError; end
  class ServerUnexpectedBehaviorError < VcertError; end
  class ClientBadDataError < VcertError; end
  class ValidationError < VcertError; end

  VCERT_PREFIX = '<Vcert>'.freeze

  # <b>DEPRECATED</b>
  # Please use <tt>VenafiConnection<tt> instead.
  #
  # This class provides an easy way to configure and retrieve a connector for a Venafi platform.
  # Usage:
  # TPP:
  #     Connection.new url: TPP_URL, user: TPP_USER, password: TPP_PASSWORD, trust_bundle: TRUST_BUNDLE
  # CLoud:
  #     Connection.new token: CLOUD_API_KEY
  #
  class Connection
    def initialize(url: nil, user: nil, password: nil, cloud_token: nil, trust_bundle:nil, fake: false)
      if fake
        @conn = FakeConnection.new
      elsif !cloud_token.nil?
        @conn = CloudConnection.new url, cloud_token
      elsif !user.nil? && !password.nil? && !url.nil?
        @conn = TPPConnection.new url, user, password, trust_bundle:trust_bundle
      else
        raise ClientBadDataError, 'Invalid credentials list'
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
    def request_and_retrieve(req, zone, timeout: TIMEOUT)
      LOG.info("#{VCERT_PREFIX} Requesting and retrieving Certificate: [#{req}], [#{zone}]")
      request zone, req
      retrieve_loop(req, timeout: timeout)
    end

    def retrieve_loop(req, timeout: TIMEOUT)
      t = Time.new + timeout
      loop do
        if Time.new > t
          LOG.info("#{VCERT_PREFIX} Waiting certificate #{req.id}")
          break
        end
        certificate = @conn.retrieve(req)
        return certificate unless certificate.nil?
        sleep 10
      end
      nil
    end

  end

  # This class provides an easy way to configure and retrieve a connector for a Venafi platform.
  # It supports the use of token authentication for TPP, and drops the use of user/password credentials.
  # Usage:
  # TPP:
  #     VenafiConnection.new url: TPP_TOKEN_URL, user: TPPUSER, password: TPPPASSWORD, trust_bundle: TRUST_BUNDLE
  #     VenafiConnection.new url: TPP_TOKEN_URL, access_token: TPP_ACCESS_TOKEN, trust_bundle: TRUST_BUNDLE
  #     VenafiConnection.new url: TPP_TOKEN_URL, refresh_token: TPP_REFRESH_TOKEN, trust_bundle: TRUST_BUNDLE
  # CLoud:
  #     VenafiConnection.new token: CLOUD_API_KEY
  #
  class VenafiConnection < Connection

    def initialize(url: nil, access_token: nil, refresh_token: nil, user: nil, password: nil, apikey: nil, trust_bundle:nil, fake: false)
      if fake
        @conn = FakeConnection.new
      elsif !cloud_token.nil?
        @conn = CloudConnection.new url, apikey
      elsif (!access_token.nil? || !refresh_token.nil? || (!user.nil? && !password.nil?)) && !url.nil?
        @conn = TokenConnection.new url, access_token: access_token, refresh_token: refresh_token, user: user,
                                    password: password, trust_bundle: trust_bundle
      else
        raise ClientBadDataError, 'Invalid credentials list'
      end
    end

    # @param [Vcert::Authentication] authentication
    # @return [Vcert::TokenInfo]
    def get_access_token(authentication: nil)
      @conn.get_access_token authentication: authentication if @conn.is_a?(Vcert::TokenConnection)
    end

    # @return [Vcert::TokenInfo]
    def refresh_access_token
      @conn.refresh_access_token if @conn.is_a?(Vcert::TokenConnection)
    end

    # @return []
    def revoke_access_token
      @conn.revoke_access_token if @conn.is_a?(Vcert::TokenConnection)
    end
  end
end

require 'fake/fake'
require 'cloud/cloud'
require 'tpp/tpp'
require 'tpp/tpp_token'
require 'objects/objects'

