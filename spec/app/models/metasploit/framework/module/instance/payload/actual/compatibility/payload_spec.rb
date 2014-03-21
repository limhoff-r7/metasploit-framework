require 'spec_helper'

describe Metasploit::Framework::Module::Instance::Payload::Actual::Compatibility::Payload do
  include_context 'Msf::Simple::Framework'

  subject(:payload_compatibility) do
    FactoryGirl.build(:metasploit_framework_module_instance_payload_actual_compatibility_payload)
  end

  # framework for Msf::Simple::Framework cleanup
  let(:framework) do
    metasploit_framework_module_instance_payload_actual_compatibility_payload.exploit_instance.framework
  end

  context 'factories' do
    context 'metasploit_framework_module_instance_payload_actual_compatibility_payload' do
      subject(:metasploit_framework_module_instance_payload_actual_compatibility_payload) do
        FactoryGirl.build(:metasploit_framework_module_instance_payload_actual_compatibility_payload)
      end

      it { should be_valid }
    end
  end

  context 'validations' do
    it { should validate_presence_of :architecture_abbreviations }
    it { should validate_presence_of :platform_fully_qualified_names }
    it { should validate_presence_of :universal_module_instance_creator }
  end

  context '#each_compatible_cache_class' do
    subject(:each_compatible_cache_class) do
      payload_compatibility.each_compatible_cache_class(options) { }
    end

    context 'with :include_generics' do
      let(:options) do
        {
            include_generics: true
        }
      end

      specify {
        expect {
          each_compatible_cache_class
        }.to raise_error ArgumentError
      }
    end

    context 'without :include_generics' do
      let(:options) do
        {}
      end

      let(:cache_module_classes) do
        cache_module_classes = []

        each_compatible_cache_class { |cache_module_class|
          cache_module_classes < cache_module_class
        }

        cache_module_classes
      end

      it 'searches for payloads' do
        expect(Mdm::Module::Instance).to receive(:with_module_type).with('payload').and_call_original

        each_compatible_cache_class
      end

      it 'searches for intersecting architecture abbreviations with #architecture_abbreviations' do
        expect(Mdm::Module::Instance).to receive(
                                             :intersecting_architecture_abbreviations
                                         ).with(
                                             payload_compatibility.architecture_abbreviations
                                         ).and_call_original

        each_compatible_cache_class
      end

      it 'searches for intersecting platform fully qualified names with #platform_fully_qualified_names' do
        expect(Mdm::Module::Instance).to receive(
                                             :intersecting_platform_fully_qualified_names
                                         ).with(
                                             payload_compatibility.platform_fully_qualified_names
                                         ).and_call_original

        each_compatible_cache_class
      end

      it 'uses Mdm::Module::Class#with_module_instances to convert Mdm::Module::Instance query to Mdm::Module::Class query' do
        expect(Mdm::Module::Class).to receive(:with_module_instances).and_call_original

        each_compatible_cache_class
      end

      it 'searches for non-generic payloads' do
        expect(Mdm::Module::Class).to receive(:non_generic_payloads).and_call_original

        each_compatible_cache_class
      end
    end
  end
end