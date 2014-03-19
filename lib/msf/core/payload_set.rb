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

  # This method is called when a new payload module class is loaded up.  For
  # the payload set we simply create an instance of the class and do some
  # magic to figure out if it's a single, stager, or stage.  Depending on
  # which it is, we add it to the appropriate list.
  #
  # @param payload_module [::Module] The module name.
  # @param reference_name [String] The module reference name.
  # @param modinfo [Hash{String => Array}] additional information about the
  #   module.
  # @option modinfo [Array<String>] 'files' List of paths to the ruby source
  #   files where +class_or_module+ is defined.
  # @option modinfo [Array<String>] 'paths' List of module reference names.
  # @option modinfo [String] 'type' The module type, should match positional
  #   +type+ argument.
  # @return [void]
  def add_module(payload_module, reference_name, modinfo={})

    if (md = reference_name.match(/^(singles|stagers|stages)#{File::SEPARATOR}(.*)$/))
      payload_type_directory = md[1]
      payload_name  = md[2]
    end

    # Duplicate the Payload base class and extend it with the module
    # class that is passed in.  This allows us to inspect the actual
    # module to see what type it is, and to grab other information for
    # our own evil purposes.
    instance = build_payload(payload_module).new

    # Create an array of information about this payload module
    pinfo =
      [
        payload_module,
        instance.handler_klass,
        instance.platform,
        instance.arch,
        instance,
        modinfo
      ]

    # Use the module's preferred alias if it has one
    payload_name = instance.alias if (instance.alias)

    # Store the module and alias name for this payload.  We
    # also convey other information about the module, such as
    # the platforms and architectures it supports
    info_by_payload_name_by_payload_type[instance.payload_type][payload_name] = pinfo
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

