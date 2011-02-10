require 'uri'
require 'openssl'
require 'base64'
require 'cgi'

class Ec2Signature

  attr_accessor :accessid, :secretkey, :ec2url, :host, :port, :path, :scheme

  def initialize creds
    raise "Need a hash of AWS/EC2 credential info" unless creds.kind_of? Hash
    [:accessid, :secretkey, :ec2url].each do |a| 
      raise "Credential hash requires :accessid, :secretkey & :ec2url" unless creds[a]
    end
    self.accessid = creds[:accessid]
    self.secretkey = creds[:secretkey]
    self.ec2url = creds[:ec2url]
    uri = URI.parse creds[:ec2url]
    self.host = uri.host
    self.scheme = uri.scheme
    self.path = uri.path
    self.port = uri.port
  end

  def sign actionparams={'Action'=>'DescribeInstances'}
    raise "hash of AWS EC2 web params action required" unless actionparams.kind_of? Hash
    raise "hash missing 'Action' key/value"  unless actionparams['Action']

    actionparams.merge!({
      'AWSAccessKeyId'    => accessid,
      'SignatureMethod'   => 'HmacSHA256',
      'SignatureVersion'  => '2',
      'Timestamp'         => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
      'Version'           => '2010-08-31'
    })

    body = ''
    for key in actionparams.keys.sort
      unless (value = actionparams[key]).nil?
        body << "#{key}=#{CGI.escape(value.to_s).gsub(/\+/, '%20')}&"
      end
    end
    string_to_sign = "POST\n#{host}:#{port}\n#{path}\n" << body.chop
    digest = OpenSSL::Digest::Digest.new('sha256')
    signed_string = OpenSSL::HMAC.digest(digest, secretkey, string_to_sign)
    body << "Signature=#{CGI.escape(Base64.encode64(signed_string).chomp!).gsub(/\+/, '%20')}"

    body
  end

  def post signature=sign
    require 'net/http'
    http = Net::HTTP.new host, port
    resp = http.post path, signature
    resp.body
  end

end
