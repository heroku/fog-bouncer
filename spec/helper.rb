if ENV['TRAVIS_PULL_REQUEST'] && ["1", "true"].include?(ENV['TRAVIS_PULL_REQUEST']) && ENV['FOG_REAL'] && ["1", "true"].include?(ENV['FOG_REAL'])
  require "clarence"
  Bitches.leave
end

require "simplecov" unless ENV['NO_SIMPLECOV']
require 'minitest/autorun'

ENV['AWS_ACCESS_KEY_ID'] ||= "abcde1234"
ENV['AWS_SECRET_ACCESS_KEY'] ||= "abcde1234"
ENV['AWS_ACCOUNT_ID'] ||= "1234567890"

require "fog/bouncer"
require "scrolls"

Scrolls::Log.stream = File.open(File.dirname(__FILE__) + '/../logs/test.log', 'w')

module TestLogger
  def self.log(data, &blk)
    Scrolls.log(data, &blk)
  end
end

Fog::Bouncer.instrument_with(TestLogger.method(:log))

def load_security(security)
  Fog::Bouncer.load File.dirname(__FILE__) + "/support/security/#{security}.rb"
end

def fog_security_groups
  Fog::Bouncer.fog.security_groups.all.reject(&:vpc_id)
end

Fog.mock! unless ENV['FOG_REAL'] && ["1", "true"].include?(ENV['FOG_REAL'])

class MiniTest::Spec
  before :each do
    Fog::Bouncer.pretend = false
  end
end

MiniTest::Unit.after_tests do
  Fog::Bouncer.doorlists.each do |name, doorlist|
    doorlist.groups.each do |group|
      group.revoke
    end

    doorlist.groups.each do |group|
      group.destroy
    end
  end
end
