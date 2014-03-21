module Msf::Framework::Modules
  # Modules that are or can be be loaded by this framework.
  #
  # @return [Metasploit::Framework::Module::Instance::Creator::Universal]
  # @raise [Metasploit::Model::Invalid] if module instance creator is invalid
  def modules
    synchronize {
      unless instance_variable_defined? :@modules
        module_instance_creator = Metasploit::Framework::Module::Instance::Creator::Universal.new(framework: self)
        module_instance_creator.valid!

        @modules = module_instance_creator
      end

      @modules
    }
  end

  Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE.each_value do |directory|
    delegate directory,
             to: :modules
  end
end