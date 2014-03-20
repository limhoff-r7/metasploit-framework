#
# Gems
#
require 'active_support/concern'

#
# Project
#

# Defines the MODULE_* constants
require 'msf/core/constants'

# Concerns the various type-specific module sets in a {Msf::ModuleManager}
module Msf::ModuleManager::ModuleSets
  extend ActiveSupport::Concern

  #
  # Instance Methods
  #

  Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE.each do |module_type, directory|
    define_method(directory) do
      module_set_by_module_type[module_type]
    end
  end

  def module_set_by_module_type
    @module_set_by_module_type ||= Metasploit::Model::Module::Type::ALL.each_with_object({}) do |module_type, module_set_by_module_type|
      module_set = Msf::ModuleSet.new(
          module_manager: self,
          module_type: module_type
      )
      module_set.valid!

      module_set_by_module_type[module_type] = module_set
    end
  end
end
