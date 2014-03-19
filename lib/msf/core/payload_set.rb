# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/module_manager'

module Msf

###
#
# This class is a special case of the generic module set class because
# payloads are generated in terms of combinations between various
# components, such as a stager and a stage.  As such, the payload set
# needs to be built on the fly and cannot be simply matched one-to-one
# with a payload module.  Yeah, the term module is kind of overloaded
# here, but eat it!
#
###
class PayloadSet < ModuleSet
  #
  # Validations
  #

  validates :module_type,
            inclusion: {
                in: [
                    Metasploit::Model::Module::Type::PAYLOAD
                ]
            }

  #
  # Methods
  #

  #
  # Creates an instance of a payload set which is just a specialized module
  # set class that has custom handling for payloads.
  #
  def initialize(attributes={})
    super

    # A hash of each of the payload types that holds an array
    # for all of the associated modules
    self.info_by_payload_name_by_payload_type = {}

    # Initialize the hash entry for each type to an empty list
    [
      Payload::Type::Single,
      Payload::Type::Stager,
      Payload::Type::Stage
    ].each { |type|
      self.info_by_payload_name_by_payload_type[type] = {}
    }

    # Initialize hashes for each of the stages and singles.  Stagers
    # never exist independent.  The stages hash will have entries that
    # point to another hash that point to the per-stager implementation
    # payload class.  For instance:
    #
    # ['windows/shell']['reverse_tcp']
    #
    # Singles will simply point to the single payload class.
    self.stages  = {}
    self.singles = {}

    # Hash that caches the sizes of payloads
    self.sizes   = {}

    # Single instance cache of modules for use with doing quick referencing
    # of attributes that would require an instance.
    self._instances = {}

    # Initializes an empty blob cache
    @blob_cache = {}
  end

  #
  # This method adds a single payload to the set and adds it to the singles
  # hash.
  #
  def add_single(p, name, modinfo)
    p.framework = framework
    p.refname = name
    p.file_path = modinfo['files'][0]

    # Associate this class with the single payload's name
    self[name] = p

    # Add the singles hash
    singles[name] = p

    dlog("Built single payload #{name}.", 'core', LEV_2)
  end

  #
  # This method adds a stage payload to the set and adds it to the stages
  # hash using the supplied handler type.
  #
  def add_stage(p, full_name, stage_name, handler_type, modinfo)
    p.framework = framework
    p.refname = full_name
    p.file_path = modinfo['files'][0]

    # Associate this stage's full name with the payload class in the set
    self[full_name] = p

    # Create the hash entry for this stage and then create
    # the associated entry for the handler type
    stages[stage_name] = {} if (!stages[stage_name])

    # Add it to this stage's stager hash
    stages[stage_name][handler_type] = p

    dlog("Built staged payload #{full_name}.", 'core', LEV_2)
  end

  #
  # Returns a single read-only instance of the supplied payload name such
  # that specific attributes, like compatibility, can be evaluated.  The
  # payload instance returned should NOT be used for anything other than
  # reading.
  #
  def instance(name)
    if (self._instances[name] == nil)
      self._instances[name] = create(name)
    end

    self._instances[name]
  end

  #
  # Returns the hash of payload stagers that have been loaded.
  #
  def stagers
    _stagers
  end

  #
  # When a payload module is reloaded, the blob cache entry associated with
  # it must be removed (if one exists)
  #
  def on_module_reload(mod)
    @blob_cache.each_key do |key|
      if key.start_with? mod.refname
        @blob_cache.delete(key)
      end
    end
  end

  #
  # The list of stages that have been loaded.
  #
  attr_reader :stages
  #
  # The list of singles that have been loaded.
  #
  attr_reader :singles
  #
  # The sizes of all the built payloads thus far.
  #
  attr_reader :sizes

protected

  #
  # Return the hash of single payloads
  #
  def _singles
    return info_by_payload_name_by_payload_type[Payload::Type::Single] || {}
  end

  #
  # Return the hash of stager payloads
  #
  def _stagers
    return info_by_payload_name_by_payload_type[Payload::Type::Stager] || {}
  end

  #
  # Return the hash of stage payloads
  #
  def _stages
    return info_by_payload_name_by_payload_type[Payload::Type::Stage] || {}
  end

  #
  # Builds a duplicate, extended version of the Payload base
  # class using the supplied modules.
  #
  def build_payload(*modules)
    klass = Class.new(Payload)

    # Remove nil modules
    modules.compact!

    # Include the modules supplied to us with the mad skillz
    # spoonfu style
    klass.include(*modules.reverse)

    return klass
  end

  attr_accessor :info_by_payload_name_by_payload_type # :nodoc:
  attr_writer   :stages, :singles, :sizes # :nodoc:
  attr_accessor :_instances # :nodoc:

end

end

