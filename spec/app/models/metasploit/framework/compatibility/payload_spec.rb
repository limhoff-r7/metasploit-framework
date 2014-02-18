require 'spec_helper'

describe Metasploit::Framework::Compatibility::Payload do
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Simple::Framework'

  subject(:payload_compatibility) do
    described_class.new(
        exploit_instance: exploit_instance
    )
  end

  #
  # Methods
  #

  def finish_module_instance(module_instance)
    module_architecture = module_instance.module_architectures.build
    module_architecture.architecture = compatible_architecture

    module_platform = module_instance.module_platforms.build
    module_platform.platform = compatible_platform

    Metasploit::Model::Module::Instance::Spec::Template.write!(module_instance: module_instance)

    module_instance.save!
  end

  #
  # lets
  #

  let(:cache_exploit_class) do
    FactoryGirl.create(
        :mdm_module_class,
        module_type: 'exploit'
    )
  end

  let(:compatible_architecture) do
    FactoryGirl.generate :mdm_architecture
  end

  let(:compatible_payload_class) do
    FactoryGirl.create(
        :mdm_module_class,
        module_type: 'payload'
    )
  end

  let(:compatible_platform) do
    FactoryGirl.generate :mdm_platform
  end

  let(:exploit_instance) do
    framework.modules.create_from_module_class(cache_exploit_class)
  end

  #
  # let!s
  #

  let!(:cache_exploit_instance) do
    FactoryGirl.build(
        :mdm_module_instance,
        module_class: cache_exploit_class,
        privileged: true,
        targets_length: 0
    ).tap { |module_instance|
      name = FactoryGirl.generate(:metasploit_model_module_target_name)
      module_target = module_instance.targets.build(
          name: name
      )

      target_architecture = module_target.target_architectures.build
      target_architecture.architecture = compatible_architecture

      target_platform = module_target.target_platforms.build
      target_platform.platform = compatible_platform

      finish_module_instance(module_instance)
    }
  end

  let!(:compatible_payload_instance) do
    FactoryGirl.build(
        :mdm_module_instance,
        module_architectures_length: 0,
        module_platforms_length: 0,
        module_class: compatible_payload_class
    ).tap { |module_instance|
      finish_module_instance(module_instance)
    }
  end

  context 'validations' do
    it { should validate_presence_of :exploit_instance }
  end

  context '#connect_exploit_instance' do
    subject(:connect_exploit_instance) do
      payload_compatibility.send(:connect_exploit_instance, payload_instance)
    end

    let(:payload_instance) do
      framework.modules.create_from_module_class(compatible_payload_class)
    end

    it 'sets payload_instance.exploit_instance to #exploit_instance' do
      expect {
        connect_exploit_instance
      }.to change(payload_instance, :exploit_instance).to(exploit_instance)
    end

    it 'merges #exploit_instance data_store to payload_instance data_store' do
      merged_value = 'merged_value'
      exploit_instance.data_store['MERGED_KEY'] = merged_value

      connect_exploit_instance

      expect(payload_instance.data_store['MERGED_KEY']).to eq(merged_value)
    end

    context 'with LHOST' do
      #
      # lets
      #

      let(:exploit_instance_local_host) do
        '12.34.56.78'
      end

      #
      # Callbacks
      #

      before(:each) do
        exploit_instance.data_store['LHOST'] = exploit_instance_local_host
        payload_instance.data_store.delete('LHOST')
      end

      it 'does not use default local host' do
        connect_exploit_instance

        expect(payload_instance.data_store['LHOST']).to eq(exploit_instance_local_host)
      end
    end

    context 'without LHOST' do
      before(:each) do
        exploit_instance.data_store.delete('LHOST')
        payload_instance.data_store.delete('LHOST')
      end

      it 'creates an Metasploit::Framework::Module::Instance::Hosts for #exploit_instance' do
        expect(Metasploit::Framework::Module::Instance::Hosts).to receive(:new).with(
                                                                      hash_including(
                                                                          metasploit_instance: exploit_instance
                                                                      )
                                                                  ).and_call_original

        connect_exploit_instance
      end

      it 'validates the Metasploit::Framework::Module::Instance::Hosts' do
        Metasploit::Framework::Module::Instance::Hosts.any_instance.should_receive(:valid!)

        connect_exploit_instance
      end

      it 'uses Metasploit::Framework::Module::Instance::Hosts#local for LHOST' do
        hosts = Metasploit::Framework::Module::Instance::Hosts.new(metasploit_instance: exploit_instance)
        connect_exploit_instance

        expect(payload_instance.data_store['LHOST']).to eq(hosts.local)
      end
    end
  end

  context '#each_compatible_cache_class' do
    def each_compatible_cache_class(&block)
      payload_compatibility.each_compatible_cache_class(&block)
    end

    it 'is abstract' do
      expect {
        each_compatible_cache_class { }
      }.to raise_error(NotImplementedError)
    end
  end

  context '#each_compatible_instance' do
    def each_compatible_instance(&block)
      payload_compatibility.each_compatible_instance(&block)
    end

    before(:each) do
      allow(payload_compatibility).to receive(:each_compatible_cache_class).and_return([compatible_payload_class])
      allow(payload_compatibility).to receive(:module_manager).and_return(framework.modules)
    end

    it 'uses Metasploit::Framework::Module::Instance::Enumerator' do
      Metasploit::Framework::Module::Instance::Enumerator.any_instance.should_receive(:each)

      each_compatible_instance { }
    end

    it 'connects exploit instance before yielding payload instance' do
      expect(payload_compatibility).to receive(:connect_exploit_instance) do |metasploit_instance|
        expect(metasploit_instance).to be_a Msf::Payload
      end

      each_compatible_instance { }
    end

    it 'yields payload instances from enumerator' do
      each_compatible_instance { |metasploit_instance|
        expect(metasploit_instance.module_instance).to eq(compatible_payload_instance)
      }
    end
  end

  context '#module_manager' do
    subject(:module_manager) do
      payload_compatibility.module_manager
    end

    it 'is abstract' do
      expect {
        module_manager
      }.to raise_error(NotImplementedError)
    end
  end
end