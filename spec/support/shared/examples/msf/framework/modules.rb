shared_examples_for 'Msf::Framework::Modules' do
  it { should be_a Msf::Framework::Modules }

  context '#modules' do
    subject(:modules) do
      framework.modules
    end

    it 'should be synchronized' do
      framework.should_receive(:synchronize)

      modules
    end

    it 'should be memoized' do
      memoized = double('Metasploit::Framework::Module::Instance::Creator::Universal')
      framework.instance_variable_set :@modules, memoized

      modules.should == memoized
    end

    it 'should pass framework to Metasploit::Framework::Module::Instance::Creator::Universal' do
      Metasploit::Framework::Module::Instance::Creator::Universal.should_receive(:new).with(
          hash_including(
              framework: framework
          )
      ).and_call_original

      modules
    end

    it 'should validate Metasploit::Framework::Module::Instance::Creator::Universal' do
      Metasploit::Framework::Module::Instance::Creator::Universal.any_instance.should_receive(:valid!)

      modules
    end

    it { should be_a Metasploit::Framework::Module::Instance::Creator::Universal }
  end

  context '#auxiliary' do
    subject(:auxiliary) do
      framework.auxiliary
    end

    it 'should delegate to #modules' do
      framework.modules.should_receive(:auxiliary)

      auxiliary
    end
  end

  context '#encoders' do
    subject(:encoders) do
      framework.encoders
    end

    it 'should delegate to #modules' do
      framework.modules.should_receive(:encoders)

      encoders
    end
  end

  context '#exploits' do
    subject(:exploits) do
      framework.exploits
    end

    it 'should delegate to #modules' do
      framework.modules.should_receive(:exploits)

      exploits
    end
  end

  context '#nops' do
    subject(:nops) do
      framework.nops
    end

    it 'should delegate to #modules' do
      framework.modules.should_receive(:nops)

      nops
    end
  end

  context '#payloads' do
    subject(:payloads) do
      framework.payloads
    end

    it 'should delegate to #modules' do
      framework.modules.should_receive(:payloads)

      payloads
    end
  end

  context '#post' do
    subject(:post) do
      framework.post
    end

    it 'should delegate to #modules' do
      framework.modules.should_receive(:post)

      post
    end
  end
end