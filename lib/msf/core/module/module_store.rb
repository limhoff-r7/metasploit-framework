module Msf::Module::ModuleStore
  #
  # Read a value from the {#module_store}
  #
  def [](k)
    self.module_store[k]
  end

  #
  # Store a value into the {#module_store}
  #
  def []=(k,v)
    self.module_store[k] = v
  end

  #
  # A generic hash used for passing additional information to modules
  #
  def module_store
    @module_store ||= {}
  end

  attr_writer :module_store
end