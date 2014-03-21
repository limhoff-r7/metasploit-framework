require 'spec_helper'

describe Msf::Payload::Generic do
  include_context 'Msf::Simple::Framework'

  subject(:payload) do
    payload_class.new(framework: framework)
  end

  let(:payload_class) do
    payload_module = self.payload_module

    Class.new(Msf::Payload) do
      include payload_module
    end
  end

  let(:payload_module) do
    described_class = self.described_class

    Module.new do
      extend  Metasploit::Framework::Module::Ancestor::Handler

      include Msf::Payload::Single
      include described_class

      handler module_name: 'Msf::Handler::None'
    end
  end

  context '#actual_compatibility' do
    subject(:actual_compatibility) do
      payload.send(:actual_compatibility)
    end

    #
    # lets
    #

    let(:explicit_architecture_abbreviation) do
      FactoryGirl.generate :metasploit_model_architecture_abbreviation
    end

    let(:explicit_architecture_abbreviations) do
      [
          explicit_architecture_abbreviation
      ]
    end

    let(:explicit_platform) do
      'Windows'
    end

    let(:explicit_platform_list) do
      Msf::Module::PlatformList.new(
          platforms: [
              explicit_platform
          ]
      )
    end

    let(:exploit_instance) do
      FactoryGirl.create(
          :msf_exploit,
          framework: framework
      )
    end

    #
    # Callbacks
    #

    before(:each) do
      payload.explicit_architecture_abbreviations = explicit_architecture_abbreviations
      payload.explicit_platform_list = explicit_platform_list
      payload.exploit_instance = exploit_instance
    end

    it { should be_a Metasploit::Framework::Module::Instance::Payload::Actual::Compatibility::Payload }

    context '#architecture_abbreviations' do
      subject(:architecture_abbreviations) do
        actual_compatibility.architecture_abbreviations
      end

      it 'is #actual_architecture_abbreviations' do
        expect(architecture_abbreviations).to equal(payload.send(:actual_architecture_abbreviations))
      end
    end

    context '#exploit_instance' do
      subject(:actual_compatibility_exploit_instance) do
        actual_compatibility.exploit_instance
      end

      it 'is #exploit_instance' do
        expect(actual_compatibility_exploit_instance).to equal(exploit_instance)
      end
    end

    context '#platform_fully_qualified_names' do
      subject(:platform_fully_qualified_names) do
        actual_compatibility.platform_fully_qualified_names
      end

      it 'is list of Metasploit::Framework::Platform#fully_qualified_names from #actual_platform_list' do
        expect(platform_fully_qualified_names).to eq([explicit_platform])
      end
    end

    context '#universal_module_instance_creator' do
      subject(:universal_module_instance_creator) do
        actual_compatibility.universal_module_instance_creator
      end

      it 'is #framework modules' do
        expect(universal_module_instance_creator).to equal(framework.modules)
      end
    end
  end
end