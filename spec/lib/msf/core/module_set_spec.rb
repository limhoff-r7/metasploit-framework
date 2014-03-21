require 'spec_helper'

describe Msf::ModuleSet do
  subject(:module_set) do
    described_class.new(
        module_type: module_type,
        universal_module_instance_creator: universal_module_instance_creator
    )
  end

  let(:module_type) do
    FactoryGirl.generate :metasploit_model_module_type
  end

  let(:universal_module_instance_creator) do
    double('Metasploit::Framework::Module::Instance::Creator::Universal')
  end

  context 'validations' do
    it { should ensure_inclusion_of(:module_type).in_array(Metasploit::Model::Module::Type::ALL) }
    it { should validate_presence_of :universal_module_instance_creator }
  end

  context '#create' do
    subject(:create) do
      module_set.create(reference_name)
    end

    let(:reference_name) do
      'module/reference/name'
    end

    let(:universal_module_instance_creator) do
      double('Metasploit::Framework::Module::Instance::Creator::Universal')
    end

    it 'calls create on #universal_module_instance_creator by prepending #module_type to reference_name' do
      expect(universal_module_instance_creator).to receive(:create).with("#{module_type}/#{reference_name}")

      create
    end
  end
end