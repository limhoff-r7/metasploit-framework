# Concerns the various type-specific module sets in a {Msf::ModuleManager}
module Msf::ModuleManager::ModuleSets
  #
  # Instance Methods
  #

  Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE.each do |module_type, directory|
    instance_variable = "@#{directory}"

    define_method(directory) do
      unless instance_variable_defined? instance_variable
        module_set = Msf::ModuleSet.new(
            module_manager: self,
            module_type: module_type
        )
        module_set.valid!

        instance_variable_set instance_variable, module_set
      end

      instance_variable_get instance_variable
    end
  end
end
