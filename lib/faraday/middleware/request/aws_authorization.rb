module Faraday
  class Request::AwsAuthorization < Faraday::Middleware
    dependency 'openssl'
    dependency 'base64'

    def initialize(app, options)
      super(app)
      @options = options
    end

    def call(env)
      date_str = Time.now.utc.strftime("%a, %d %b %Y %H:%M:%S +0000") 
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
      content_md5 = env[:request_headers]["Content-MD5"] || ""
      content_type = env[:request_headers]["Content-Type"] || ""
      amz_headers = canonicalized_aws_headers(env[:request_headers])
      resource = canonicalized_resource(env)
      [
        http_verb,
        content_md5,
        content_type,
        date_str,
        amz_headers + resource,
      ].join("\n")
    end
    def canonicalized_aws_headers(headers)
      ret = ""
      headers.sort_by{|k,v| k}.each do |key, value|
        value = value.to_s.strip
        if key =~ /x-amz-/i
          ret << "#{key.downcase}:#{value}"
          ret << "\n"
        end
      end
      ret
    end
    def canonicalized_resource(env)
      # todo hosted style
      resource = ""
      resource << env[:url].path
      resource << "?#{env[:url].query}" if env[:url].query
      resource
    end
  end
end

