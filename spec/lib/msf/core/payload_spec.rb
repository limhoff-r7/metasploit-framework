require 'spec_helper'

describe Msf::Payload do
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Simple::Framework'

  shared_context '#compatible_cache_nop_instances' do
    #
    # lets
    #

    let(:cache_payload_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: 'payload'
      )
    end

    let(:compatible_cache_architecture) do
      FactoryGirl.generate :mdm_architecture
    end

    let(:compatible_cache_nop_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: 'nop'
      )
    end

    let(:incompatible_cache_architecture) do
      FactoryGirl.generate :mdm_architecture
    end

    let(:incompatible_cache_nop_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: 'nop'
      )
    end

    let(:payload) do
      framework.modules.create_from_module_class(cache_payload_class)
    end

    #
    # let!s
    #

    let!(:cache_payload_instance) do
      FactoryGirl.build(
          :mdm_module_instance,
          module_architectures_length: 0,
          module_class: cache_payload_class
      ).tap { |cache_payload_instance|
        module_architecture = cache_payload_instance.module_architectures.build
        module_architecture.architecture = compatible_cache_architecture

        cache_payload_instance.save!

        Metasploit::Model::Module::Instance::Spec::Template.write(module_instance: cache_payload_instance)
      }
    end

    let!(:compatible_cache_nop_instance) do
      FactoryGirl.build(
          :mdm_module_instance,
          module_architectures_length: 0,
          module_class: compatible_cache_nop_class
      ).tap { |cache_nop_instance|
        module_architecture = cache_nop_instance.module_architectures.build
        module_architecture.architecture = compatible_cache_architecture

        cache_nop_instance.save!

        Metasploit::Model::Module::Instance::Spec::Template.write(module_instance: cache_nop_instance)
      }
    end

    let!(:incompatible_cache_nop_instance) do
      FactoryGirl.build(
          :mdm_module_instance,
          module_architectures_length: 0,
          module_class: incompatible_cache_nop_class
      ).tap { |cache_nop_instance|
        module_architecture = cache_nop_instance.module_architectures.build
        module_architecture.architecture = incompatible_cache_architecture

        cache_nop_instance.save!

        Metasploit::Model::Module::Instance::Spec::Template.write(module_instance: cache_nop_instance)
      }
    end
  end

  subject(:payload_instance) do
    framework.modules.create_from_module_class(cache_payload_instance.module_class)
  end

  #
  # lets
  #

  let(:cache_payload_class) do
    FactoryGirl.create(
        :mdm_module_class,
        module_type: 'payload'
    )
  end

  let(:cache_payload_instance) do
    FactoryGirl.create(
        :mdm_module_instance,
        module_class: cache_payload_class
    )
  end

  it 'should extend Metasploit::Framework::Module::Class::Handler' do
    described_class.should be_a Metasploit::Framework::Module::Class::Handler
  end

  it_should_behave_like 'Msf::Module::SaveRegisters' do
    let(:metasploit_instance) do
      payload_instance
    end
  end

  context '#compatible_cache_nop_instances' do
    include_context '#compatible_cache_nop_instances'

    subject(:compatible_cache_nop_instances) do
      payload.compatible_cache_nop_instances
    end

    it 'includes compatible Mdm::Module::Instances' do
      expect(compatible_cache_nop_instances).to include(compatible_cache_nop_instance)
    end

    it 'excludes incompatible Mdm::Module::Instances' do
      expect(compatible_cache_nop_instances).not_to include(incompatible_cache_nop_instance)
    end
  end

  context '#compatible_nop_instances' do
    include_context '#compatible_cache_nop_instances'

    subject(:compatible_nop_instances) do
      payload.compatible_nop_instances
    end

    it { should be_a Metasploit::Framework::Module::Instance::Enumerator }

    it 'uses Mdm::Module::Class.with_module_instances to convert #compatible_cache_nop_instances to an Mdm::Module::Class scope' do
      compatible_cache_nop_instances = double('#compatible_cache_nop_instances')
      expect(payload).to receive(:compatible_cache_nop_instances).and_return(compatible_cache_nop_instances)
      expect(Mdm::Module::Class).to receive(:with_module_instances).with(compatible_cache_nop_instances).and_return(Mdm::Module::Class.scoped)

      compatible_nop_instances
    end

    context 'Metasploit::Framework::Module::Instance::Enumerator' do
      subject(:enumerator) do
        compatible_nop_instances
      end

      it 'is validated' do
        Metasploit::Framework::Module::Instance::Enumerator.any_instance.should_receive :valid!

        enumerator
      end

      context '#each' do
        it 'yields compatible instances' do
          enumerator.each do |nop_instance|
            expect(nop_instance.module_instance).to eq(compatible_cache_nop_instance)
          end
        end

        it 'does not yield incompatible instances' do
          enumerator.each do |nop_instance|
            expect(nop_instance.module_instance).not_to eq(incompatible_cache_nop_instance)
          end
        end
      end

      context '#module_manager' do
        subject(:module_manager) do
          enumerator.module_manager
        end

        it 'is the Msf::Framework#modules' do
          expect(module_manager).to eq(payload.framework.modules)
        end
      end
    end
  end

	context 'type' do
    subject(:type) do
			described_class.type
		end

		it 'should be Metasploit::Model::Module::Type::PAYLOAD' do
			type.should == Metasploit::Model::Module::Type::PAYLOAD
		end
	end
end