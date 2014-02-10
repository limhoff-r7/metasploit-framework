require 'spec_helper'

describe Metasploit::Framework::Module::Instance::Enumerator do
  include_context 'Msf::Simple::Framework'

  subject(:enumerator) do
    described_class.new(
        cache_module_classes: cache_module_classes,
        module_manager: module_manager
    )
  end

  let(:cache_module_classes) do
    FactoryGirl.create_list(:mdm_module_class, 2)
  end

  let(:module_manager) do
    framework.modules
  end

  it { should be_a Enumerable }

  context 'validations' do
    it { should validate_presence_of :cache_module_classes }
    it { should validate_presence_of :module_manager }
  end

  context '#each' do
    subject(:each) do
      enumerator.each(&block)
    end

    context 'with block' do
      #
      # lets
      #

      let(:block) do
        ->(module_instance){}
      end

      let(:creatable_cache_module_class) do
        cache_module_classes.last
      end

      let(:uncreatable_cache_module_class) do
        cache_module_classes.first
      end

      #
      # Callbacks
      #

      before(:each) do
        uncreatable_cache_module_class.ancestors.each do |module_ancestor|
          File.delete module_ancestor.real_path
        end
      end

      it 'enumerates #cache_module_classes' do
        expect(cache_module_classes).to receive(:each)

        each
      end

      it 'creates each Msf::Module with module_manager.create_from_module_class' do
        cache_module_classes.each do |cache_module_class|
          expect(module_manager).to receive(:create_from_module_class).with(cache_module_class)
        end

        each
      end

      it 'does not yield nil module_instances from Mdm::Module::Classes that could not be created' do
        count = 0

        enumerator.each do |module_instance|
          count += 1

          expect(module_instance).not_to be_nil
        end

        expect(count).to be > 0
      end

      it 'logs error when a module fails to be created' do
        expect(enumerator).to receive(:elog)

        each
      end

      it 'includes the module class locaton in the error' do
        expect(enumerator).to receive(:elog) do |message|
          module_class_module = Metasploit::Framework::Module::Class::Logging.module_class_location(uncreatable_cache_module_class)
          expect(message).to include(module_class_location)
        end

        each
      end

      it 'yields module instance that could be created' do
        count = 0

        enumerator.each do |module_instance|
          count += 1

          expect(module_instance.class.module_class).to be(creatable_cache_module_class)
        end

        expect(count).to be > 0
      end
    end

    context 'without block' do
      let(:block) do
        nil
      end

      it { should be_a Enumerator }
    end
  end
end