require 'msf/core/option_container'

module Msf::Module::Options
  require 'msf/core/module/data_store'
  include Msf::Module::DataStore

  require 'msf/core/module/module_info'
  include Msf::Module::ModuleInfo

  #
  # Methods
  #

  #
  # Removes the supplied options from the module's option container
  # and data store.
  #
  def deregister_options(*names)
    names.each { |name|
      self.options.remove_option(name)
      self.datastore.delete(name)
    }
  end

  def options
    unless instance_variable_defined? :@options
      @options = Msf::OptionContainer.new

      ['', 'Advanced', 'Evasion'].each do |option_type|
        method_name_parts = ['add', option_type.underscore, 'options'].reject(&:blank?)
        method_name = method_name_parts.join('_')

        module_info_options = module_info["#{option_type}Options"]
        options.send(method_name, module_info_options, self.class)
      end

      @options = options
    end

    @options
  end

  attr_writer :options

  #
  # Register advanced options with a specific owning class.
  #
  def register_advanced_options(options, owner = self.class)
    self.options.add_advanced_options(options, owner)
    self.datastore.import_options(self.options, 'self', true)
    import_defaults(false)
  end

  #
  # Register evasion options with a specific owning class.
  #
  def register_evasion_options(options, owner = self.class)
    self.options.add_evasion_options(options, owner)
    self.datastore.import_options(self.options, 'self', true)
    import_defaults(false)
  end

  # Register options with a specific owning class.
  #
  def register_options(options, owner = self.class)
    self.options.add_options(options, owner)
    self.datastore.import_options(self.options, 'self', true)
    import_defaults(false)
  end
end