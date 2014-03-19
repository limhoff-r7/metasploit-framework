require 'msf/core/module_manager'

module Msf::Framework::Modules
  # Modules that are or can be be loaded by this framework.
  #
  # @return [Msf::ModuleManager]
  # @raise [Metasploit::Model::Invalid] if module manager is invalid
  def modules
    synchronize {
      unless instance_variable_defined? :@modules
        module_manager = Msf::ModuleManager.new(framework: self)
        module_manager.valid!

        @modules = module_manager
      end

      @modules
    }
  end

  Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE.each_value do |directory|
    delegate directory,
             to: :modules
  end
end