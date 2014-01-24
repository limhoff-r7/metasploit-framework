require 'msf/core/module_data_store'

module Msf::Module::DataStore
  # (see #data_store)
  # @deprecated Use {#data_store}
  def datastore
    ActiveSupport::Deprecation.warn "#{self.class}##{__method__} is deprecated.  Use #{self.class}#data_store instead"
    data_store
  end

  # Data Store for this module that defers to the {Msf::Module#framework} {Msf::Framework#datastore} if a variable is not
  # set for this module specifically.
  #
  # @return [Msf::ModuleDataStore]
  def data_store
    unless instance_variable_defined? :@data_store
      @data_store = Msf::ModuleDataStore.new(self)

      import_defaults
    end

    @data_store
  end

  attr_writer :data_store

  #
  # Imports default options into the module's datastore, optionally clearing
  # all of the values currently set in the datastore.
  #
  # @param options [Hash{Symbol => Boolean}]
  # @option options [Boolean] :clear_data_store (true) `Hash#clear` the {#data_store} before importing the defaults.
  # @return [void]
  def import_defaults(options={})
    options.assert_valid_keys(:clear_data_store)

    clear_data_store = options.fetch(:clear_data_store, true)

    # Clear the datastore if the caller asked us to
    data_store.clear if clear_data_store

    data_store.import_options(self.options, 'self', true)

    # If there are default options, import their values into the datastore
    default_options = module_info['DefaultOptions']

    if default_options
      data_store.import_options_from_hash(default_options, true, 'self')
    end
  end

  # Overrides the class' own datastore with the one supplied.  This is used
  # to allow modules to share datastores, such as a payload sharing an
  # exploit module's datastore.
  #
  def share_datastore(ds)
    self.datastore = ds
    self.datastore.import_options(self.options)
  end
end