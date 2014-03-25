require 'spec_helper'

describe Msf::Simple::Module do
  shared_context 'framework' do
    include_context 'Msf::Simple::Framework'

    before(:each) do
      simple_module.framework = framework
    end
  end

  subject(:simple_module) do
    Msf::Module.new.tap { |metasploit_instance|
      metasploit_instance.extend Msf::Simple::Module
    }
  end

  context '#inspect' do
    subject(:inspect) do
      simple_module.inspect
    end

    #
    # lets
    #

    let(:data_store) do
      Msf::DataStore.new.tap { |data_store|
        data_store['DATA_STORE_KEY'] = 'DATA_STORE_VALUE'
      }
    end

    let(:full_name) do
      'full/module/name'
    end

    #
    # Callbacks
    #

    before(:each) do
      simple_module.stub(
          data_store: data_store,
          full_name: full_name
      )
    end

    it 'includes #data_store' do
      inspect.should include data_store.inspect
    end

    it 'includes #full_name' do
      inspect.should include full_name
    end
  end

  context '#load_config' do
    include_context 'framework'

    subject(:load_config) do
      simple_module.load_config
    end

    it 'calls #reference_name' do
      simple_module.data_store.stub(:from_file)

      simple_module.should_receive(:reference_name)

      load_config
    end
  end

  context '#save_config' do
    include_context 'framework'

    subject(:save_config) do
      simple_module.save_config
    end

    it 'calls #reference_name' do
      simple_module.data_store.stub(:to_file)

      simple_module.should_receive(:reference_name)

      save_config
    end
  end
end