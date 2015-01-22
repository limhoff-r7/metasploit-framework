module Msf::ModuleManager::ModuleSets
  #
  # Returns the set of loaded auxiliary module classes.
  #
  def auxiliary
    module_set(MODULE_AUX)
  end

  #
  # Returns the set of loaded encoder module classes.
  #
  def encoders
    module_set(MODULE_ENCODER)
  end

  #
  # Returns the set of loaded exploit module classes.
  #
  def exploits
    module_set(MODULE_EXPLOIT)
  end

  def init_module_set(type)
    self.enabled_types[type] = true
    case type
    when MODULE_PAYLOAD
      instance = PayloadSet.new(self)
    else
      instance = ModuleSet.new(type)
    end

    self.module_sets[type] = instance

    # Set the module set's framework reference
    instance.framework = self.framework
  end

  #
  # Provide a list of module names of a specific type
  #
  def module_names(set)
    module_sets[set] ? module_sets[set].keys.dup : []
  end

  #
  # Returns all of the modules of the specified type
  #
  def module_set(type)
    module_sets[type]
  end

  #
  # Provide a list of the types of modules in the set
  #
  def module_types
    module_sets.keys.dup
  end

  #
  # Returns the set of loaded nop module classes.
  #
  def nops
    module_set(MODULE_NOP)
  end

  #
  # Returns the set of loaded payload module classes.
  #
  def payloads
    module_set(MODULE_PAYLOAD)
  end

  #
  # Returns the set of loaded auxiliary module classes.
  #
  def post
    module_set(MODULE_POST)
  end

  protected

  attr_accessor :enabled_types
  attr_accessor :module_sets
end