shared_examples_for 'Msf::Simple::Framework::ModulePaths#add_named_module_paths' do |options={}|
  options.assert_valid_keys(:config_directory_name, :name)

  config_directory_name = options.fetch(:config_directory_name)
  name = options.fetch(:name)
  config_method = "#{config_directory_name}_directory".to_sym

  context config_directory_name.to_s do
    context 'with present' do
      let(config_method) do
        FactoryGirl.generate :metasploit_model_module_path_real_path
      end

      it "should add gem: 'metasploit-framework', name: '#{name}'" do
        expect(path_set).not_to receive(:add).with(
                                    send(config_method),
                                    hash_including(
                                        gem: 'metasploit-framework',
                                        name: name
                                    )
                                )

        add_named_module_paths
      end
    end

    context 'without present' do
      let(config_method) do
        nil
      end

      it "should not add gem: 'metasploit-framework', name: '#{name}'" do
        expect(path_set).not_to receive(:add_path).with(
                                    anything,
                                    hash_including(
                                        gem: 'metasploit-framework',
                                        name: name
                                    )
                                )

        add_named_module_paths
      end
    end
  end
end