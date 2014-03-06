module Msf
  module Simple
    module Framework
      module ModulePaths
        # Adds {#data_store_module_paths datastore module paths} to this framework.
        #
        # @return [void]
        def add_data_store_module_paths
          data_store_module_paths.each do |data_store_module_path|
            modules.add_path(data_store_module_path, prefetch: false)
          end
        end

        # Add {#data_store_module_paths datastore module paths} and {#module_path_value_by_name named module paths} to
        # this framework.
        #
        # @return [void]
        def add_module_paths
          add_data_store_module_paths
          add_named_module_paths
        end

        # Adds {#module_path_value_by_name named module paths} to this framework.
        #
        # @return [void]
        def add_named_module_paths
          module_path_value_by_name.each do |name, value|
            if value
              modules.add_path(value, gem: 'metasploit-framework', name: name, prefetch: false)
            end
          end
        end

        # Module paths saved to 'MsfModulePaths' in this framework.
        #
        # @return [Array<String>]
        def data_store_module_paths
          formatted_data_store_module_paths = data_store['MsfModulePaths']

          data_store_module_paths = []

          unless formatted_data_store_module_paths.blank?
            data_store_module_paths = formatted_data_store_module_paths.split(';')
          end

          data_store_module_paths
        end

        # Maps `Metasploit::Model::Module::Path#real_path` to its `Metasploit::Model::Module::Path#name` in the
        # 'metasploit-framework' `Metasploit::Model::Module::Path#gem` namespace.
        #
        # @return [Hash{String => String, nil}]
        def module_path_value_by_name
          @module_path_value_by_name ||= {
              'modules' => Metasploit::Framework.pathnames.modules.to_path,
              'user' => pathnames.modules.to_path
          }
        end
      end
    end
  end
end