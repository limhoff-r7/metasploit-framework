shared_context 'Metasploit::Framework::Attempt::Creation::Base' do
  include_context 'database cleaner'
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Simple::Framework'

  #
  # lets
  #

  let(:attempted_at) do
    Time.now.utc - rand(10.years)
  end

  let(:cache_exploit_class) do
    # Different than exploit_class.module_class to simulate ParentModule behavior used for exploit/multi/handler
    cache_module_instance.module_class
  end

  let(:cache_module_instance) do
    FactoryGirl.create(:mdm_module_instance)
  end

  let(:exploit_class) do
    # exploits only have one metasploit_class
    exploit_module.each_metasploit_class.first
  end

  let(:exploit_instance) do
    exploit_class.new(framework: framework)
  end

  let(:exploit_module) do
    module_ancestor_load.metasploit_module
  end

  let(:exploited) do
    [false, true].sample
  end

  let(:module_ancestor) do
    module_path.module_ancestors.new(real_path: module_ancestor_real_path)
  end

  let(:module_ancestor_load) do
    Metasploit::Framework::Module::Ancestor::Load.new(module_ancestor: module_ancestor)
  end

  let(:module_ancestor_real_path) do
    module_ancestor_real_paths.sample
  end

  let(:module_ancestor_real_paths) do
    File::Find.new(
        ftype: 'file',
        path: File.join(module_path.real_path, 'exploits'),
        pattern: "*#{Metasploit::Model::Module::Ancestor::EXTENSION}"
    ).find
  end

  let(:module_path) do
    FactoryGirl.create(
        :mdm_module_path,
        gem: 'metasploit-framework',
        name: 'modules',
        real_path: Metasploit::Framework.root.join('modules').to_path
    )
  end

  #
  # Callbacks
  #

  before(:each) do
    framework.cache.write_module_ancestor_load(module_ancestor_load)
  end
end