shared_examples_for 'Msf::Module::Platforms' do
  let(:metasploit_instance) do
    described_class.new(
        'Platform' => platform_fully_qualified_names
    )
  end

  let(:module_class) do
    FactoryGirl.create(:mdm_module_class)
  end

  let(:platforms) do
    Metasploit::Framework::Platform.all.sample(2)
  end

  let(:platform_fully_qualified_names) do
    platforms.map(&:fully_qualified_name)
  end

  #
  # Callbacks
  #

  before(:each) do
    metasploit_instance.stub_chain(:class, :module_class).and_return(module_class)
  end

  context '#platform_list' do
    include_context 'database cleaner'

    subject(:platform_list) do
      metasploit_instance.platform_list
    end

    #
    # lets
    #

    let(:module_class_full_name) do
      module_class.full_name
    end

    it 'calls Msf::Module::PlatformList.transform' do
      Msf::Module::PlatformList.should_receive(:transform).with(
          platform_fully_qualified_names,
          hash_including(
              module_class_full_names: [
                  module_class_full_name
              ]
          )
      )

      platform_list
    end
  end

  context '#platform_list_to_s' do
    subject(:platform_list_to_s) do
      metasploit_instance.platform_list_to_s
    end

    let(:platform_fully_qualified_names) do
      [
          'Windows',
          'Linux'
      ]
    end

    it 'is a comma separated list of sorted fully qualified names' do
      expect(platform_list_to_s).to eq('Linux, Windows')
    end
  end
end