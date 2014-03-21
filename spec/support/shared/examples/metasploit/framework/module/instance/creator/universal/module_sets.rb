shared_examples_for 'Metasploit::Framework::Module::Instance::Creator::Universal::ModuleSets' do
  context '#auxiliary' do
    subject(:auxiliary) do
      module_instance_creator.auxiliary
    end

    it { should be_a Msf::ModuleSet }
    its(:module_type) { should == 'auxiliary' }
  end

  context '#encoders' do
    subject(:encoders) do
      module_instance_creator.encoders
    end

    it { should be_a Msf::ModuleSet }
    its(:module_type) { should == 'encoder' }
  end

  context '#exploits' do
    subject(:exploits) do
      module_instance_creator.exploits
    end

    it { should be_a Msf::ModuleSet }
    its(:module_type) { should == 'exploit' }
  end

  context '#nops' do
    subject(:nops) do
      module_instance_creator.nops
    end

    it { should be_a Msf::ModuleSet }
    its(:module_type) { should == 'nop' }
  end

  context '#payloads' do
    subject(:payloads) do
      module_instance_creator.payloads
    end

    it { should be_a Msf::ModuleSet }
    its(:module_type) { should == 'payload' }
  end

  context '#post' do
    subject(:post) do
      module_instance_creator.post
    end

    it { should be_a Msf::ModuleSet }
    its(:module_type) { should == 'post' }
  end
end