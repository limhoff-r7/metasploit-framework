# -*- coding: binary -*-

#
# Gems
#

require 'ice_nine'

#
# Project
#

require 'msf/core'

# The module base class is responsible for providing the common interface
# that is used to interact with modules at the most basic levels, such as
# by inspecting a given module's attributes (name, dsecription, version,
# authors, etc) and by managing the module's data store.
class Msf::Module < Metasploit::Model::Base

  require 'msf/core/module/auxiliary_action'
  require 'msf/core/module/deprecated'
  require 'msf/core/module/has_actions'
  require 'msf/core/module/reference'
  require 'msf/core/module/site_reference'
  require 'msf/core/module/target'

  require 'msf/core/module/architectures'
  include Msf::Module::Architectures

  require 'msf/core/module/authors'
  include Msf::Module::Authors

  require 'msf/core/module/compatibility'
  include Msf::Module::Compatibility

  require 'msf/core/module/data_store'
  include Msf::Module::DataStore

  require 'msf/core/module/full_name'
  include Msf::Module::FullName

  require 'msf/core/module/module_info'
  include Msf::Module::ModuleInfo

  require 'msf/core/module/module_store'
  include Msf::Module::ModuleStore

  require 'msf/core/module/options'
  include Msf::Module::Options

  require 'msf/core/module/platforms'
  include Msf::Module::Platforms

  require 'msf/core/module/rank'
  include Msf::Module::Rank

  require 'msf/core/module/type'
  include Msf::Module::Type

  require 'msf/core/module/ui'
  include Msf::Module::UI

  require 'msf/core/module/workspace'
  include Msf::Module::Workspace

  # Make include public so we can runtime extend
  public_class_method :include

  #
  # CONSTANTS
  #

  # Attributes that are skipped when {#replicant} dupes ivars
  MANUALLY_SET_REPLICANT_IVAR_NAMES = [:@data_store, :@framework, :@module_store, :@user_input, :@user_output]

  #
  # Attributes
  #

  # @!attribute [rw] error
  #   The last exception to occur using this module.
  #
  #   @return [Exception]
  attr_accessor :error

  # @!attribute [rw] framework
  #   The framework to which this metasploit instance belongs.
  #
  #   @return [Msf::Simple::Framework]
  attr_accessor :framework


  # @!attribute [rw] job_id
  #   The job identifier that this module is running as, if any.
  #
  #   @return [Integer]
  attr_accessor :job_id

  #
  # Validations
  #

  validates :framework,
            presence: true

  #
  # Methods
  #

  # Returns the module's alias, if it has one.  Otherwise, the module's
  # name is returned.
  #
  def alias
    module_info['Alias']
  end

  #
  # The default communication subsystem for this module.  We may need to move
  # this somewhere else.
  #
  def comm
    return Rex::Socket::Comm::Local
  end

  #
  # Returns true if this module is being debugged.  The debug flag is set
  # by setting data_store['DEBUG'] to 1|true|yes
  #
  def debugging?
    (data_store['DEBUG'] || '') =~ /^(1|t|y)/i
  end

  # Checks to see if a derived instance of a given module implements a method
  # beyond the one that is provided by a base class.  This is a pretty lame
  # way of doing it, but I couldn't find a better one, so meh.
  #
  def derived_implementor?(parent, method_name)
    (self.method(method_name).to_s.match(/#{parent}[^:]/)) ? false : true
  end

  #
  # Return the module's description.
  #
  def description
    module_info['Description']
  end

  #
  # Returns the disclosure date, if known.
  #
  def disclosure_date
    Date.parse(module_info['DisclosureDate'].to_s) rescue nil
  end

  alias_method :disclosed_on, :disclosure_date

  #
  # Support fail_with for all module types, allow specific classes to override
  #
  def fail_with(reason, msg=nil)
    raise RuntimeError, "#{reason.to_s}: #{msg}"
  end

  #
  # Creates an instance of an abstract module using the supplied information
  # hash.
  #
  def initialize(info = {})
    attributes = {}
    module_info = {}

    info.each do |key, value|
      # symbol keys are assumed by attributes that can be processed by Metasploit::Model::Base#initialize
      if key.is_a? Symbol
        attributes[key] = value
      else
        module_info[key] = value
      end
    end

    # module_info itself is an attribute
    attributes[:module_info] = module_info

    super(attributes)
  end

  # This method allows modules to tell the framework if they are usable
  # on the system that they are being loaded on in a generic fashion.
  # By default, all modules are indicated as being usable.  An example of
  # where this is useful is if the module depends on something external to
  # ruby, such as a binary.
  #
  def self.is_usable
    true
  end

  def license
    @license ||= module_info['License'] || MSF_LICENSE
  end

  attr_writer :license

  # The module's name from {Msf::Module::ModuleInfo#module_info}
  #
  # @return [String]
  def name
    module_info['Name']
  end

  #
  # Returns the username that instantiated this module, this tries a handful of methods
  # to determine what actual user ran this module.
  #
  def owner
    # Generic method to configure a module owner
    username = self.data_store['MODULE_OWNER'].to_s.strip

    # Specific method used by the commercial products
    if username.empty?
      username = self.data_store['PROUSER'].to_s.strip
    end

    # Fallback when neither prior method is available, common for msfconsole
    if username.empty?
      username = (ENV['LOGNAME'] || ENV['USERNAME'] || ENV['USER'] || "unknown").to_s.strip
    end

    username
  end

  def privileged
    unless instance_variable_defined? :@privileged
      @privileged = module_info['Privileged'] || false
    end

    @privileged
  end

  #
  # Returns whether or not the module requires or grants high privileges.
  #
  def privileged?
    !!privileged
  end

  attr_writer   :privileged

  def references
    unless instance_variable_defined? :@references
      @references = Rex::Transformer.transform(
          module_info['References'],
          Array,
          [
              Msf::Module::SiteReference,
              Msf::Module::Reference
          ],
          'Ref'
      )
    end

    @references
  end

  attr_writer :references

  #
  # Scans the parent module reference to populate additional information. This
  # is used to inherit common settings (owner, workspace, parent uuid, etc).
  #
  def register_parent(ref)
    self.data_store['WORKSPACE']    = (ref.data_store['WORKSPACE'] ? ref.data_store['WORKSPACE'].dup : nil)
    self.data_store['PROUSER']      = (ref.data_store['PROUSER']   ? ref.data_store['PROUSER'].dup   : nil)
    self.data_store['MODULE_OWNER'] = ref.owner.dup
  end

  # Creates a fresh copy of an instantiated module, retaining the original framework
  # @return [Msf::Module]
  def replicant
    obj = self.class.new(framework: self.framework)

    self.instance_variables.each { |k|
      next if MANUALLY_SET_REPLICANT_IVAR_NAMES.include? k
      v = instance_variable_get(k)
      v = v.dup rescue v
      obj.instance_variable_set(k, v)
    }

    obj.data_store   = self.data_store.copy
    obj.user_input   = self.user_input
    obj.user_output  = self.user_output
    obj.module_store = self.module_store.clone
    obj
  end

  #
  # Indicates whether the module supports IPv6. This is true by default,
  # but certain modules require additional work to be compatible or are
  # hardcoded in terms of application support and should be skipped.
  #
  def support_ipv6?
    true
  end

  #
  # Returns the address of the last target host (rough estimate)
  #
  def target_host
    if(self.respond_to?('rhost'))
      return rhost()
    end

    if(self.data_store['RHOST'])
      return self.data_store['RHOST']
    end

    nil
  end

  #
  # Returns the address of the last target port (rough estimate)
  #
  def target_port
    if(self.respond_to?('rport'))
      return rport()
    end

    if(self.data_store['RPORT'])
      return self.data_store['RPORT']
    end

    nil
  end

  # A unique identifier for this module instance
  #
  def uuid
    @uuid ||= SecureRandom.uuid
  end

  attr_writer :uuid

  #
  # This method ensures that the options associated with this module all
  # have valid values according to each required option in the option
  # container.
  #
  def validate
    self.options.validate(self.data_store)
  end
end
