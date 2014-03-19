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

  module ClassMethods
    def module_set_class_by_module_type
      unless instance_variable_defined? :@module_set_class_by_module_type
        @module_set_class_by_module_type ||= Hash.new { |hash, module_type|
          hash[module_type] = Msf::ModuleSet
        }
      end

      @module_set_class_by_module_type
    end
  end

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
      module_set_class = self.class.module_set_class_by_module_type[module_type]
      module_set = module_set_class.new(
          module_manager: self,
          module_type: module_type
      )
      module_set.valid!

      module_set_by_module_type[module_type] = module_set
    end
  end
end
