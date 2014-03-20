require 'spec_helper'

describe Msf::Simple::Statistics do
  include_context 'Msf::Simple::Framework'

  shared_context 'Mdm::Module::Classes' do
    include_context 'database cleaner'

    before(:each) do
      Metasploit::Model::Module::Type::NON_PAYLOAD.each do |module_type|
        FactoryGirl.create(
            :mdm_module_class,
            module_type: module_type
        )
      end

      Metasploit::Model::Module::Class::PAYLOAD_TYPES.each do |payload_type|
        FactoryGirl.create(
            :mdm_module_class,
            module_type: 'payload',
            payload_type: payload_type
        )
      end
    end
  end

  subject(:statistics) do
    framework.stats
  end

  context '#num_auxiliary' do
    include_context 'Mdm::Module::Classes'

    subject(:num_auxiliary) do
      statistics.num_auxiliary
    end

    it "counts number of Mdm::Module::Classes with Mdm::Module::Class#module_type of 'auxiliary'" do
      expect(num_auxiliary).to eq(1)
    end
  end

  context '#num_encoders' do
    include_context 'Mdm::Module::Classes'

    subject(:num_encoders) do
      statistics.num_encoders
    end

    it "counts number of Mdm::Module::Classes with Mdm::Module::Class#module_type of 'encoder'" do
      expect(num_encoders).to eq(1)
    end
  end

  context '#num_exploits' do
    include_context 'Mdm::Module::Classes'

    subject(:num_exploits) do
      statistics.num_exploits
    end

    it "counts number of Mdm::Module::Classes with Mdm::Module::Class#module_type of 'exploit'" do
      expect(num_exploits).to eq(1)
    end
  end

  context '#num_nops' do
    include_context 'Mdm::Module::Classes'

    subject(:num_nops) do
      statistics.num_nops
    end

    it "counts number of Mdm::Module::Classes with Mdm::Module::Class#module_type of 'nop'" do
      expect(num_nops).to eq(1)
    end
  end

  context '#num_payloads' do
    include_context 'Mdm::Module::Classes'

    subject(:num_payloads) do
      statistics.num_payloads
    end

    it "counts number of Mdm::Module::Classes with Mdm::Module::Class#module_type of 'payload'" do
      expect(num_payloads).to eq(Metasploit::Model::Module::Class::PAYLOAD_TYPES.length)
    end
  end

  context '#num_post' do
    include_context 'Mdm::Module::Classes'

    subject(:num_post) do
      statistics.num_post
    end

    it "counts number of Mdm::Module::Classes with Mdm::Module::Class#module_type of 'post'" do
      expect(num_post).to eq(1)
    end
  end
end