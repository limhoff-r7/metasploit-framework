require 'spec_helper'

describe Metasploit::Framework::Module::Instance::Synchronization::Base do
  subject(:synchronization) do
    described_class.new
  end

  it { should be_a Metasploit::Framework::Module::Instance::Logging }
  it { should be_a Metasploit::Framework::Synchronization::Destination }
end