# Concerns the various type-specific module sets in a {Metasploit::Framework::Module::Instance::Creator::Universal}
module Metasploit::Framework::Module::Instance::Creator::Universal::ModuleSets
  #
  # Instance Methods
  #

  Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE.each do |module_type, directory|
    instance_variable = "@#{directory}"

    define_method(directory) do
      unless instance_variable_defined? instance_variable
        module_set = Msf::ModuleSet.new(
            module_type: module_type,
            universal_module_instance_creator: self
        )
        module_set.valid!

        instance_variable_set instance_variable, module_set
      end

      instance_variable_get instance_variable
    end
  end
end
