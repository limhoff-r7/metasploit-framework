module Metasploit::Framework::Transactional
  extend ActiveSupport::Concern

  include Metasploit::Framework::Transaction

  module ClassMethods
    def transactional(method_name)
      # defines Class.<method_name>
      define_singleton_method(method_name) do |&block|
        #
        # Module look up needs to be performed inside the call to this class method so that subclasses get different
        # modules.
        #

        inherit = false
        module_name = 'Transactional'

        # Define methods in an included module so that super calls from inside the class call methods defined dynamically
        if const_defined?(module_name, inherit)
          method_module = const_get(module_name, inherit)
        else
          method_module = const_set(module_name, Module.new)
          include method_module
        end

        # defines Class#<method_name> using block passed to Class.<method_name>, but on the included module so that
        # the Class can override and use super
        method_module.module_eval do
          define_method(method_name) do
            transaction {
              instance_eval(&block)
            }
          end
        end
      end
    end
  end
end