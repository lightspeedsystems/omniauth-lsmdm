require 'omniauth-oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    class lsmdm < OmniAuth::Strategies::OAuth2
      option :name, :lsmdm
      option :client_options, {:authorize_path => '/oauth/authorize',
                               :site => 'http://api.lsmdm.com'}

      uid { raw_info["id"] }

      info do
        {
          :first_name => raw_info['first_name'],
          :last_name => raw_info['last_name'],
          :email => raw_info['email'],
          :mobile_phone_number => raw_info['mobile_phone_number']
        }
      end

      def raw_info
        @raw_info ||= access_token.get('/1/credentials/verify.json').parsed
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

    end
  end
end
