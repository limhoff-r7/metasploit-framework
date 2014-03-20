# -*- coding: binary -*-

# Statistics about {Metasploit::Framework}
module Metasploit::Framework::Statistics
  Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE.each do |module_type, directory|
    define_singleton_method("num_#{directory}") do
      Mdm::Module::Class.where(module_type: module_type).count
    end
  end
end
