require 'test_helper'

describe EC2Signature do
  describe '#new' do
    it 'should accept :awsaccessid, :awssecretkey, :ec2url' do 
      assert EC2Signature.new({:awsaccessid => 1, :awssecretkey => 2, :ec2url => 'http://blah.com/some/yo'})
    end
    it 'should throw an error if missing :ec2url' do
      proc { EC2Signature.new({:awsaccessid => 1, :awssecretkey => 2}) }.must_raise RuntimeError
    end
    it 'should throw an error if missing :awssecretkey' do
      proc {EC2Signature.new({:awsaccessid => 1, :ec2url => 'http://blah.com/some/yo'}) }.must_raise RuntimeError
    end
     it 'should throw an error if missing :awsaccessid' do
      proc {EC2Signature.new({:awssecretkey => 2, :ec2url => 'http://blah.com/some/yo'}) }.must_raise RuntimeError
    end
    it 'should create an EC2Signature class obj' do
      EC2Signature.new({:awsaccessid => 1, :awssecretkey => 2, :ec2url => 'http://blah.com/some/yo'}).must_be_kind_of EC2Signature
    end
  end # describe '#new' do

  describe 'the instance' do
    before do 
      @ec2 = EC2Signature.new({:awsaccessid => 1, :awssecretkey => 2, :ec2url => 'http://blah.com:112/some/yo'})
    end
    it 'should have an :awsaccessid attribute' do
      assert @ec2.awsaccessid
      assert_equal @ec2.awsaccessid, 1
    end
    it 'should have an :awssecretkey attribute' do
      assert_equal @ec2.awssecretkey, 2
    end
    it 'should have an :ec2url attribute' do
      assert_equal @ec2.ec2url, 'http://blah.com:112/some/yo'
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
  end
end
