# Concerns the various type-specific module instance creators in a
# {Metasploit::Framework::Module::Instance::Creator::Universal}
module Metasploit::Framework::Module::Instance::Creator::Universal::Types
  #
  # Instance Methods
  #

  Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE.each do |module_type, directory|
    instance_variable = "@#{directory}"

    define_method(directory) do
      unless instance_variable_defined? instance_variable
        type_module_instance_creator = Metasploit::Framework::Module::Instance::Creator::Type.new(
            module_type: module_type,
            universal_module_instance_creator: self
        )
        type_module_instance_creator.valid!

        instance_variable_set instance_variable, type_module_instance_creator
      end

      instance_variable_get instance_variable
    end
  end
end
