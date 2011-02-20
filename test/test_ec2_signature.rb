require 'test_helper'

$creds = {:awsaccessid => 'abc123', :awssecretkey => '12i3jfae138', :ec2url => 'http://blah.com:112/some/yo'}

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
  end

end
