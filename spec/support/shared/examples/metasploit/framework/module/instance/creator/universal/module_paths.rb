shared_examples_for 'Metasploit::Framework::Module::Instance::Creator::Universal::ModulePaths' do
  context '#add_path' do
    include_context 'database cleaner'

    subject(:add_path) do
      module_instance_creator.add_path(path, options)
    end

    let(:cache) do
      module_instance_creator.cache
    end

    let(:path) do
      FactoryGirl.generate :metasploit_model_module_path_real_path
    end

    let(:path_set) do
      cache.path_set
    end

    context 'with options' do
      let(:gem) do
        'metasploit-framework'
      end

      let(:name) do
        'spec'
      end

      let(:options) do
        {
            gem: gem,
            name: name,
            prefetch: prefetch
        }
      end

      let(:prefetch) do
        true
      end

      it 'should pass :gem and :name options to Metasploit::Framework::PathSet::Base#add' do
        path_set.should_receive(:add).with(
            path,
            hash_including(
                gem: gem,
                name: name
            )
        )

        add_path
      end

      it 'should not pass :prefetch option to Metasploit::Framework::PathSet::Base#add' do
        path_set.should_receive(:add).with(
            path,
            hash_excluding(
                :prefetch
            )
        )

        add_path
      end

      context ':prefetch' do
        context 'with false' do
          let(:prefetch) do
            false
          end

          it 'should not prefetch Metasploit::Model::Module::Path' do
            cache.should_not_receive(:prefetch)

            add_path
          end

          context 'Metasploit::Model::Module::Path' do
            subject(:module_path) do
              Mdm::Module::Path.first
            end

            before(:each) do
              add_path
            end

            it { should be_a Metasploit::Model::Module::Path }

            it 'should have Metasploit::Model::Module::Path#gem equal to :gem option' do
              module_path.gem.should == gem
            end

            it 'should have Metasploit::Model::Module::Path#name equal to :name option' do
              module_path.name.should == name
            end

            it 'should have Metasploit::Model::Module::Path#real_path equal to path argument (converted to real path)' do
              module_path.real_path.should == path
            end
          end
        end

        context 'with true' do
          let(:prefetch) do
            true
          end

          it 'should prefetch added Metasploit::Model::Module::Path' do
            cache.should_receive(:prefetch) do |options|
              options.should have_key(:only)
              options[:only].should be_a Metasploit::Model::Module::Path

              # Array<Metasploit::Framework::Module::Path>
              []
            end

            add_path
          end

          context 'Metasploit::Model::Module::Path' do
            subject(:module_path) do
              Mdm::Module::Path.first
            end

            before(:each) do
              add_path
            end

            it 'should have Metasploit::Model::Module::Path#gem equal to :gem option' do
              module_path.gem.should == gem
            end

            it 'should have Metasploit::Model::Module::Path#name equal to :name option' do
              module_path.name.should == name
            end

            it 'should have Metasploit::Model::Module::Path#real_path equal to path argument (converted to real path)' do
              module_path.real_path.should == path
            end
          end
        end
      end
    end

    context 'without options' do
      subject(:add_path) do
        module_instance_creator.add_path(path)
      end

      it 'should not pass :prefetch option to Metasploit::Framework::Module::PathSet::Base#add' do
        path_set.should_receive(:add).with(
            path,
            hash_excluding(:prefetch)
        )

        add_path
      end

      it 'should pass nil for :gem and :name' do
        path_set.should_receive(:add).with(
            path,
            hash_including(
                gem: nil,
                name: nil
            )
        )

        add_path
      end

      it 'should default to prefetch: true' do
        cache.should_receive(:prefetch).and_return []

        add_path
      end
    end
  end
end