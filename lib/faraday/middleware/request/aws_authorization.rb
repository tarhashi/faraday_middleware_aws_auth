module Faraday
  class Request::AwsAuthorization < Faraday::Middleware
    dependency 'openssl'
    dependency 'base64'

    def initialize(app, options)
      super(app)
      @options = options
    end

    def call(env)
      date_str = Time.now.strftime("%a, %d %b %Y %H:%M:%S +0000") 
      env[:request_headers]["Date"] = date_str
      env[:request_headers]["Authorization"] = "AWS #{@options[:access_key_id]}:#{sign(env, @options[:secret_access_key], date_str)}"
      @app.call(env)
    end

    private
    def sign(env, secret_access_key, date_str)
      digest = OpenSSL::Digest::Digest.new('sha1')
      signature = OpenSSL::HMAC.digest(digest, secret_access_key, string_to_sign(env, date_str))
      Base64.encode64(signature).strip
    end
    def string_to_sign(env, date_str)
      http_verb = env[:method].to_s.upcase
      content_md5 = "" # todo implement
      content_type = "" # todo implement
      amz_headers = ""
      # todo query string
      # todo hosted style
      resource = env[:url].path
      resource += env[:url].query if env[:url].query
      [
        http_verb,
        content_md5,
        content_type,
        date_str,
        amz_headers + resource,
      ].join("\n")
    end
  end
end

