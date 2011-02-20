require 'test_helper'
require 'cgi'

$creds = {:awsaccessid => 'abc123', :awssecretkey => '12i3jfae138', :ec2url => 'http://blah.com:112/some/yo'}
$timestamp = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

describe EC2Signature do
  describe '#new' do
    it 'should accept :awsaccessid, :awssecretkey, :ec2url' do 
      assert EC2Signature.new $creds
    end
    it 'should throw an error if missing :ec2url' do
      tmpcreds = $creds.dup.delete :ec2url
      proc { EC2Signature.new tmpcreds }.must_raise RuntimeError
    end
    it 'should throw an error if missing :awssecretkey' do
      tmpcreds = $creds.dup.delete :awssecretkey
      proc {EC2Signature.new tmpcreds }.must_raise RuntimeError
    end
     it 'should throw an error if missing :awsaccessid' do
      tmpcreds = $creds.dup.delete :awsaccessid
      proc {EC2Signature.new tmpcreds}.must_raise RuntimeError
    end
    it 'should create an EC2Signature class obj' do
      EC2Signature.new($creds).must_be_kind_of EC2Signature
    end
    it 'should only allow GET or POST methods' do
      proc {EC2Signature.new $creds, 'PUT' }.must_raise RuntimeError
      assert EC2Signature.new $creds, 'GET'
    end
  end # describe '#new' do

  describe 'the instance' do
    before do 
      @ec2 = EC2Signature.new $creds
    end
    it 'should have an :awsaccessid attribute' do
      assert @ec2.awsaccessid
      assert_equal @ec2.awsaccessid, $creds[:awsaccessid]
    end
    it 'should have an :awssecretkey attribute' do
      assert_equal @ec2.awssecretkey, $creds[:awssecretkey]
    end
    it 'should have an :ec2url attribute' do
      assert_equal @ec2.ec2url, $creds[:ec2url]
    end
    it 'should have a :host attribute parsed from the ec2url' do
      assert_equal @ec2.host, 'blah.com'
    end
    it 'should have a :port attribute parsed from the ec2url' do
      assert_equal @ec2.port, 112
    end
    it 'should have a :path attribute parsed from the ec2url' do 
      assert_equal @ec2.path, '/some/yo'
    end
    it 'should have a :scheme attribute parsed from the ec2url' do 
      assert_equal @ec2.scheme, 'http'
    end
    it 'should have a :method attribute and default value should be POST' do
      assert_equal @ec2.method, 'POST'
    end
    it 'should start with a nil project' do
      @ec2.project.must_be_nil
    end
    it 'should allow you to set a project' do
      @ec2.project='testproject'.must_equal 'testproject'
    end
    it 'should start with a nil signature' do
      @ec2.signature.must_be_nil
    end
  end # describe 'the instance' do

  describe '#sign' do
    before do 
      @ec2 = EC2Signature.new $creds
    end

    it 'should require no args' do
      @ec2.sign.must_be_kind_of EC2Signature
      @ec2.signature.wont_be_nil
    end
    it 'should default to DescribeInstances action param' do
      @ec2.sign.signature.must_match /Action=DescribeInstances/
    end
    it 'should allow custom ec2 action string' do
      @ec2.sign('DescribeImages').signature.must_match /Action=DescribeImages/
    end
    it 'should allow custom ec2 action strings that have more than one query param' do
      actionparams = {'Name' => 'ami1390'}
      @ec2.sign('DescribeImage', actionparams).signature.must_match /Action=DescribeImage&Name=ami1390/
    end
    it 'should allow specify a timestamp' do
      @ec2.sign('DescribeInstances',{},$timestamp).signature.must_match /Timestamp=#{CGI::escape $timestamp}/
    end
    it 'should return an ec2 compatible signature' do
      known_timestamp = '2011-02-20T06:25:50Z'
      known_signature = 'AWSAccessKeyId=abc123&Action=DescribeInstances&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=2011-02-20T06%3A25%3A50Z&Version=2010-08-31&Signature=0fuHYXhygt2osdqtnRww1WFR2nHMwk0wvhiCOxuS3AY%3D'
      @ec2.sign('DescribeInstances',{},known_timestamp).signature.must_equal known_signature
    end
    it 'should append the ":project" string to awsaccessid in the signature (cgi escaped)' do
      @ec2.sign.signature.must_match /KeyId=#{$creds[:awsaccessid]}&Action/ # before specifying project
      @ec2.project = 'someproj'
      @ec2.sign.signature.must_match /KeyId=#{CGI::escape $creds[:awsaccessid]+':someproj'}/
    end
  end # describe '#sign' do

  describe '#submit' do
    $xml = "<?xml version=\"1.0\" ?><DescribeInstancesResponse xmlns=\"http://ec2.amazonaws.com/doc/2010-08-31/\"><requestId>G4DU2RXB59NMIX84UW9F</requestId><reservationSet><item><ownerId>jsmith</ownerId><groupSet><item><groupId>default</groupId></item></groupSet><reservationId>r-5oexkoz1</reservationId><instancesSet><item><displayDescription/><displayName>Server 198</displayName><keyName>None (jsmith, cm-02)</keyName><instanceId>i-000000c6</instanceId><instanceState><code>1</code><name>running</name></instanceState><publicDnsName/><imageId>ami-usc3oydl</imageId><productCodesSet/><privateDnsName>10.1.1.17</privateDnsName><dnsName>10.1.1.17</dnsName><launchTime>2011-02-20 07:17:03</launchTime><placement><availabilityZone>nova</availabilityZone></placement><amiLaunchIndex>0</amiLaunchIndex><instanceType>m1.small</instanceType></item></instancesSet></item></reservationSet></DescribeInstancesResponse>"

    before do
      FakeWeb.register_uri(:post, $creds[:ec2url], :body => $xml)
      @ec2 = EC2Signature.new $creds
    end

    it 'by default should submit via POST' do
      @ec2.submit.must_be_kind_of Hash
    end
    it 'should allow you to also submit via GET' do
      FakeWeb.register_uri(:get, %r|#{$creds[:ec2url]}|, :body => $xml)
      @ec2.method = 'GET'
      @ec2.submit.must_be_kind_of Hash
    end
    it 'by default should return a Hash' do
      @ec2.submit.must_be_kind_of Hash
    end
    it 'should allow you to return the raw xml instead of Hash' do
      # the catch is that you won't be able to use the default arg param values
      raw = @ec2.submit('DescribeInstances', {}, $timestamp, true)
      raw.must_be_kind_of String
      raw.must_match /<?xml version=\"1.0\"/
    end
  end # describe '#submit' do

end
