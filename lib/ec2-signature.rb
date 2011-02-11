require 'uri'
require 'openssl'
require 'base64'
require 'cgi'

class EC2Signature

  attr_accessor :awsaccessid, :awssecretkey, :ec2url, :host, :port, :path, :scheme, :method
  attr_accessor :signature

  def initialize creds, method='POST'
    raise "Need a hash of AWS/EC2 credential info" unless creds.kind_of? Hash
    [:awsaccessid, :awssecretkey, :ec2url].each do |a| 
      raise "Credential hash requires :awsaccessid, :awssecretkey & :ec2url" unless creds[a]
    end
    raise "Method can only be 'GET' or 'POST'" unless ['GET','POST'].include? method
    self.awsaccessid = creds[:awsaccessid]
    self.awssecretkey = creds[:awssecretkey]
    self.ec2url = creds[:ec2url]
    uri = URI.parse creds[:ec2url]
    self.host = uri.host
    self.scheme = uri.scheme
    self.path = uri.path
    self.port = uri.port
    self.method = method
  end

  def sign actionparams={'Action'=>'DescribeInstances'}
    raise "hash of AWS EC2 web params action required" unless actionparams.kind_of? Hash
    raise "hash missing 'Action' key/value"  unless actionparams['Action']

    actionparams.merge!({
      'AWSAccessKeyId'    => awsaccessid,
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
    string_to_sign = "#{method}\n#{host}:#{port}\n#{path}\n" << body.chop
    digest = OpenSSL::Digest::Digest.new('sha256')
    signed_string = OpenSSL::HMAC.digest(digest, awssecretkey, string_to_sign)
    body << "Signature=#{CGI.escape(Base64.encode64(signed_string).chomp!).gsub(/\+/, '%20')}"
    self.signature = body
    self
  end

  def submit signature=signature
    require 'net/http'
    http = Net::HTTP.new host, port
    resp = case method
      when 'GET' then http.get path.concat('?'+signature)
      when 'POST' then http.post path, signature
    end
    resp.body
  end

end
