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
  def import_defaults(clear_datastore = true)
    # Clear the datastore if the caller asked us to
    self.datastore.clear if clear_datastore

    self.datastore.import_options(self.options, 'self', true)

    # If there are default options, import their values into the datastore
    if (module_info['DefaultOptions'])
      self.datastore.import_options_from_hash(module_info['DefaultOptions'], true, 'self')
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