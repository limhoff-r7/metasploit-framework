shared_examples_for 'Metasploit::Framework::Module::Instance::Creator::Universal::Cache' do
  context '#cache' do
    subject(:cache) do
      module_instance_creator.cache
    end

    it 'should be memoized' do
      memoized = double('Metasploit::Framework::Module::Cache')
      module_instance_creator.instance_variable_set :@cache, memoized

      cache.should == memoized
    end

    it 'should be validated' do
      Metasploit::Framework::Module::Cache.any_instance.should_receive(:valid!)

      cache
    end

    it { should be_a Metasploit::Framework::Module::Cache }

    context '#universal_module_instance_creator' do
      subject(:cache_universal_module_instance_creator) do
        cache.universal_module_instance_creator
      end

      it 'is parent Metasploit::Framework::Module::Instance::Creator::Universal' do
        expect(cache_universal_module_instance_creator).to equal(module_instance_creator)
      end
    end
  end
end