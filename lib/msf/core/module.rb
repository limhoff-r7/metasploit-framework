# -*- coding: binary -*-
require 'msf/core'

module Msf

###
#
# The module base class is responsible for providing the common interface
# that is used to interact with modules at the most basic levels, such as
# by inspecting a given module's attributes (name, dsecription, version,
# authors, etc) and by managing the module's data store.
#
###
class Module < Metasploit::Model::Base
  require 'msf/core/module/reference'
  require 'msf/core/module/target'
  require 'msf/core/module/auxiliary_action'
  require 'msf/core/module/has_actions'

  require 'msf/core/module/architectures'
  include Msf::Module::Architectures

  require 'msf/core/module/authors'
  include Msf::Module::Authors

  require 'msf/core/module/full_name'
  include Msf::Module::FullName

  require 'msf/core/module/platforms'
  include Msf::Module::Platforms

  require 'msf/core/module/rank'
  include Msf::Module::Rank

  require 'msf/core/module/type'
  include Msf::Module::Type

  # Modules can subscribe to a user-interface, and as such they include the
  # UI subscriber module.  This provides methods like print, print_line, etc.
  # User interfaces are designed to be medium independent, and as such the
  # user interface subscribes are designed to provide a flexible way of
  # interacting with the user, n stuff.
  include Rex::Ui::Subscriber

  # Make include public so we can runtime extend
  public_class_method :include

  #
  # Attributes
  #

  # @!attribute [rw] framework
  #   The framework to which this metasploit instance belongs.
  #
  #   @return [Msf::Simple::Framework]
  attr_accessor :framework

  #
  # Validations
  #

  validates :framework,
            presence: true

  #
  # Methods
  #

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

    super(attributes)

    self.module_info = module_info.dup

    set_defaults

    # Initialize module compatibility hashes
    init_compat

    # Fixup module fields as needed
    info_fixups

    # Transform some of the fields to arrays as necessary
    self.references = Rex::Transformer.transform(module_info['References'], Array, [ SiteReference, Reference ], 'Ref')

    # Create and initialize the option container for this module
    self.options = OptionContainer.new
    self.options.add_options(info['Options'], self.class)
    self.options.add_advanced_options(info['AdvancedOptions'], self.class)
    self.options.add_evasion_options(info['EvasionOptions'], self.class)

    # Create and initialize the data store for this module
    self.datastore = ModuleDataStore.new(self)

    # Import default options into the datastore
    import_defaults

    self.privileged = module_info['Privileged'] || false
    self.license = module_info['License'] || MSF_LICENSE

    # Allow all modules to track their current workspace
    register_advanced_options(
      [
        OptString.new('WORKSPACE', [ false, "Specify the workspace for this module" ]),
        OptBool.new('VERBOSE',     [ false, 'Enable detailed status messages', false ])
      ], Msf::Module)

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

  #
  # Creates a fresh copy of an instantiated module
  #
  def replicant

    obj = self.class.new
    self.instance_variables.each { |k|
      v = instance_variable_get(k)
      v = v.dup rescue v
      obj.instance_variable_set(k, v)
    }

    obj.datastore    = self.datastore.copy
    obj.user_input   = self.user_input
    obj.user_output  = self.user_output
    obj.module_store = self.module_store.clone
    obj
  end

  #
  # Overwrite the Subscriber print_(status|error|good) to do time stamps
  #

  def print_prefix
    if (datastore['TimestampOutput'] =~ /^(t|y|1)/i) || (
      framework && framework.datastore['TimestampOutput'] =~ /^(t|y|1)/i
    )
      prefix = "[#{Time.now.strftime("%Y.%m.%d-%H:%M:%S")}] "

      xn ||= datastore['ExploitNumber']
      xn ||= framework.datastore['ExploitNumber']
      if xn.is_a?(Fixnum)
        prefix << "[%04d] " % xn
      end

      return prefix
    else
      return ''
    end
  end

  def print_status(msg='')
    super(print_prefix + msg)
  end

  def print_error(msg='')
    super(print_prefix + msg)
  end

  def print_good(msg='')
    super(print_prefix + msg)
  end

  def print_warning(msg='')
    super(print_prefix + msg)
  end


  #
  # Overwrite the Subscriber print_line to do custom prefixes
  #

  def print_line_prefix
    datastore['CustomPrintPrefix'] || framework.datastore['CustomPrintPrefix'] || ''
  end

  def print_line(msg='')
    super(print_line_prefix + msg)
  end

  # Verbose version of #print_status
  def vprint_status(msg)
    print_status(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end
  # Verbose version of #print_error
  def vprint_error(msg)
    print_error(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end
  # Verbose version of #print_good
  def vprint_good(msg)
    print_good(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end
  # Verbose version of #print_line
  def vprint_line(msg)
    print_line(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end
  # Verbose version of #print_debug
  def vprint_debug(msg)
    print_debug(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end
  # Verbose version of #print_warning
  def vprint_warning(msg)
    print_warning(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end

  #
  # Returns the unduplicated class associated with this module.
  #
  def orig_cls
    return self.class.orig_cls
  end

  #
  # The path to the file in which the module can be loaded from.
  #
  def file_path
    self.class.file_path
  end

  #
  # Return the module's name from the module information hash.
  #
  def name
    module_info['Name']
  end

  #
  # Returns the module's alias, if it has one.  Otherwise, the module's
  # name is returned.
  #
  def alias
    module_info['Alias']
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
    date_str = Date.parse(module_info['DisclosureDate'].to_s) rescue nil
  end

  #
  # Returns the hash that describes this module's compatibilities.
  #
  def compat
    module_info['Compat'] || {}
  end

  #
  # Returns the address of the last target host (rough estimate)
  #
  def target_host
    if(self.respond_to?('rhost'))
      return rhost()
    end

    if(self.datastore['RHOST'])
      return self.datastore['RHOST']
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

    if(self.datastore['RPORT'])
      return self.datastore['RPORT']
    end

    nil
  end

  # Returns the current `Mdm::Workspace#name`
  #
  # @return [String] `Mdm::Workspace#name`
  def workspace
    workspace_name = datastore['WORKSPACE']

    unless workspace_name
      framework.db.with_connection {
        workspace = framework.db.workspace

        if workspace
          workspace_name = workspace.name
        end
      }
    end

    workspace_name
  end

  #
  # Returns the username that instantiated this module, this tries a handful of methods
  # to determine what actual user ran this module.
  #
  def owner
    # Generic method to configure a module owner
    username = self.datastore['MODULE_OWNER'].to_s.strip

    # Specific method used by the commercial products
    if username.empty?
      username = self.datastore['PROUSER'].to_s.strip
    end

    # Fallback when neither prior method is available, common for msfconsole
    if username.empty?
      username = (ENV['LOGNAME'] || ENV['USERNAME'] || ENV['USER'] || "unknown").to_s.strip
    end

    username
  end

  #
  # Scans the parent module reference to populate additional information. This
  # is used to inherit common settings (owner, workspace, parent uuid, etc).
  #
  def register_parent(ref)
    self.datastore['WORKSPACE']    = (ref.datastore['WORKSPACE'] ? ref.datastore['WORKSPACE'].dup : nil)
    self.datastore['PROUSER']      = (ref.datastore['PROUSER']   ? ref.datastore['PROUSER'].dup   : nil)
    self.datastore['MODULE_OWNER'] = ref.owner.dup
    self.datastore['ParentUUID']   = ref.uuid.dup
  end

  #
  # Returns whether or not this module is compatible with the supplied
  # module.
  #
  def compatible?(mod)
    ch = nil

    # Invalid module?  Shoot, we can't compare that.
    return true if (mod == nil)

    # Determine which hash to used based on the supplied module type
    case mod.module_type
      when Metasploit::Model::Module::Type::ENCODER
        ch = self.compat['Encoder']
      when Metasploit::Model::Module::Type::NOP
        ch = self.compat['Nop']
      when Metasploit::Model::Module::Type::PAYLOAD
        ch = self.compat['Payload']
      else
        return true
    end

    # Enumerate each compatibility item in our hash to find out
    # if we're compatible with this sucker.
    ch.each_pair do |k,v|

      # Get the value of the current key from the module, such as
      # the ConnectionType for a stager (ws2ord, for instance).
      mval = mod.module_info[k]

      # Reject a filled compat item on one side, but not the other
      if (v and not mval)
        dlog("Module #{mod.full_name} is incompatible with #{self.full_name} for #{k}: limiter was #{v}")
        return false
      end

      # Track how many of our values matched the module
      mcnt = 0

      # Values are whitespace separated
      sv = v.split(/\s+/)
      mv = mval.split(/\s+/)

      sv.each do |x|

        dlog("Checking compat [#{mod.full_name} with #{self.full_name}]: #{x} to #{mv.join(", ")}", 'core', LEV_3)

        # Verify that any negate values are not matched
        if (x[0,1] == '-' and mv.include?(x[1, x.length-1]))
          dlog("Module #{mod.refname} is incompatible with #{self.full_name} for #{k}: limiter was #{x}, value was #{mval}", 'core', LEV_1)
          return false
        end

        mcnt += 1 if mv.include?(x)
      end

      # No values matched, reject this module
      if (mcnt == 0)
        dlog("Module #{mod.full_name} is incompatible with #{self.full_name} for #{k}: limiter was #{v}, value was #{mval}", 'core', LEV_1)
        return false
      end

    end

    dlog("Module #{mod.full_name} is compatible with #{self.full_name}", "core", LEV_1)


    # If we get here, we're compatible.
    return true
  end

  #
  # Returns whether or not the module requires or grants high privileges.
  #
  def privileged?
    return (privileged == true)
  end

  #
  # The default communication subsystem for this module.  We may need to move
  # this somewhere else.
  #
  def comm
    return Rex::Socket::Comm::Local
  end

  #
  # Overrides the class' own datastore with the one supplied.  This is used
  # to allow modules to share datastores, such as a payload sharing an
  # exploit module's datastore.
  #
  def share_datastore(ds)
    self.datastore = ds
    self.datastore.import_options(self.options)
  end

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

  #
  # This method ensures that the options associated with this module all
  # have valid values according to each required option in the option
  # container.
  #
  def validate
    self.options.validate(self.datastore)
  end

  #
  # Returns true if this module is being debugged.  The debug flag is set
  # by setting datastore['DEBUG'] to 1|true|yes
  #
  def debugging?
    (datastore['DEBUG'] || '') =~ /^(1|t|y)/i
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
  # This provides a standard set of search filters for every module.
  # The search terms are in the form of:
  #   {
  #     "text" => [  [ "include_term1", "include_term2", ...], [ "exclude_term1", "exclude_term2"], ... ],
  #     "cve" => [  [ "include_term1", "include_term2", ...], [ "exclude_term1", "exclude_term2"], ... ]
  #   }
  #
  # Returns true on no match, false on match
  #
  def search_filter(search_string)
    return false if not search_string

    search_string += " "

    # Split search terms by space, but allow quoted strings
    terms = search_string.split(/\"/).collect{|t| t.strip==t ? t : t.split(' ')}.flatten
    terms.delete('')

    # All terms are either included or excluded
    res = {}

    terms.each do |t|
      f,v = t.split(":", 2)
      if not v
        v = f
        f = 'text'
      end
      next if v.length == 0
      f.downcase!
      v.downcase!
      res[f] ||=[   [],    []   ]
      if v[0,1] == "-"
        next if v.length == 1
        res[f][1] << v[1,v.length-1]
      else
        res[f][0] << v
      end
    end

    k = res

    refs = self.references.map{|x| [x.ctx_id, x.ctx_val].join("-") }
    is_server    = (self.respond_to?(:stance) and self.stance.aggressive?)
    is_client    = (self.respond_to?(:stance) and self.stance.passive?)

    [0,1].each do |mode|
      match = false
      k.keys.each do |t|
        next if k[t][mode].length == 0

        k[t][mode].each do |w|
          # Reset the match flag for each keyword for inclusive search
          match = false if mode == 0

          # Convert into a case-insensitive regex
          r = Regexp.new(Regexp.escape(w), true)

          case t
            when 'text'
              terms = [self.name, self.full_name, self.description] + refs + self.author.map{|x| x.to_s}
              if self.respond_to?(:targets) and self.targets
                terms = terms + self.targets.map{|x| x.name}
              end
              match = [t,w] if terms.any? { |x| x =~ r }
            when 'name'
              match = [t,w] if self.name =~ r
            when 'path'
              match = [t,w] if self.full_name =~ r
            when 'author'
              match = [t,w] if self.author.map{|x| x.to_s}.any? { |a| a =~ r }
            when 'os', 'platform'
              match = [t,w] if self.platform_to_s =~ r or self.arch_to_s =~ r
              if not match and self.respond_to?(:targets) and self.targets
                match = [t,w] if self.targets.map{|x| x.name}.any? { |t| t =~ r }
              end
            when 'port'
              match = [t,w] if self.datastore['RPORT'].to_s =~ r
            when 'type'
              match = [t,w] if Msf::MODULE_TYPES.any? { |modt| w == modt and self.type == modt }
            when 'app'
              match = [t,w] if (w == "server" and is_server)
              match = [t,w] if (w == "client" and is_client)
            when 'cve'
              match = [t,w] if refs.any? { |ref| ref =~ /^cve\-/i and ref =~ r }
            when 'bid'
              match = [t,w] if refs.any? { |ref| ref =~ /^bid\-/i and ref =~ r }
            when 'osvdb'
              match = [t,w] if refs.any? { |ref| ref =~ /^osvdb\-/i and ref =~ r }
            when 'edb'
              match = [t,w] if refs.any? { |ref| ref =~ /^edb\-/i and ref =~ r }
          end
          break if match
        end
        # Filter this module if no matches for a given keyword type
        if mode == 0 and not match
          return true
        end
      end
      # Filter this module if we matched an exclusion keyword (-value)
      if mode == 1 and match
        return true
      end
    end

    false
  end

  #
  # Support fail_with for all module types, allow specific classes to override
  #
  def fail_with(reason, msg=nil)
    raise RuntimeError, "#{reason.to_s}: #{msg}"
  end

  #
  # Read a value from the module store
  #
  def [](k)
    self.module_store[k]
  end

  #
  # Store a value into the module
  #
  def []=(k,v)
    self.module_store[k] = v
  end

  #
  # The reference count for the module.
  #
  attr_reader   :references
  #
  # The module-specific datastore instance.
  #
  attr_reader   :datastore
  #
  # The module-specific options.
  #
  attr_reader   :options
  #
  # Whether or not this module requires privileged access.
  #
  attr_reader   :privileged
  #
  # The license under which this module is provided.
  #
  attr_reader   :license

  #
  # The job identifier that this module is running as, if any.
  #
  attr_accessor :job_id

  #
  # A generic hash used for passing additional information to modules
  #
  attr_accessor :module_store

  #
  # The last exception to occur using this module
  #
  attr_accessor :error

  #
  # A unique identifier for this module instance
  #

  def uuid
    @uuid ||= Rex::Text.rand_text_alphanumeric(8).downcase
  end
  attr_reader :uuid

protected
  attr_writer :uuid

  #
  # The list of options that support merging in an information hash.
  #
  UpdateableOptions = [ "Name", "Description", "Alias", "PayloadCompat" ]

  #
  # Sets the modules unsupplied info fields to their default values.
  #
  def set_defaults
    self.module_info = {
      'Name'        => nil,
      'Description' => nil,
      'Version'     => '0',
      'Author'      => nil,
      'Arch'        => nil, # No architectures by default.
      'Platform'    => [],  # No platforms by default.
      'Ref'         => nil,
      'Privileged'  => false,
      'License'     => MSF_LICENSE,
    }.update(self.module_info)
    self.module_store = {}
  end

  #
  # This method initializes the module's compatibility hashes by normalizing
  # them into one single hash.  As it stands, modules can define
  # compatibility in their supplied info hash through:
  #
  # Compat::        direct compat definitions
  # PayloadCompat:: payload compatibilities
  # EncoderCompat:: encoder compatibilities
  # NopCompat::     nop compatibilities
  #
  # In the end, the module specific compatibilities are merged as sub-hashes
  # of the primary Compat hash key to make checks more uniform.
  #
  def init_compat
    c = module_info['Compat']

    if (c == nil)
      c = module_info['Compat'] = Hash.new
    end

    # Initialize the module sub compatibilities
    c['Payload'] = Hash.new if (c['Payload'] == nil)
    c['Encoder'] = Hash.new if (c['Encoder'] == nil)
    c['Nop']     = Hash.new if (c['Nop'] == nil)

    # Update the compat-derived module specific compatibilities from
    # the specific ones to make a uniform view of compatibilities
    c['Payload'].update(module_info['PayloadCompat'] || {})
    c['Encoder'].update(module_info['EncoderCompat'] || {})
    c['Nop'].update(module_info['NopCompat'] || {})
  end

  #
  # Register options with a specific owning class.
  #
  def info_fixups
    # Each reference should be an array consisting of two elements
    refs = module_info['References']
    if(refs and not refs.empty?)
      refs.each_index do |i|
        if !(refs[i].respond_to?('[]') and refs[i].length == 2)
          refs[i] = nil
        end
      end

      # Purge invalid references
      refs.delete(nil)
    end
  end

  #
  # Register options with a specific owning class.
  #
  def register_options(options, owner = self.class)
    self.options.add_options(options, owner)
    self.datastore.import_options(self.options, 'self', true)
    import_defaults(false)
  end

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

  #
  # Checks to see if a derived instance of a given module implements a method
  # beyond the one that is provided by a base class.  This is a pretty lame
  # way of doing it, but I couldn't find a better one, so meh.
  #
  def derived_implementor?(parent, method_name)
    (self.method(method_name).to_s.match(/#{parent}[^:]/)) ? false : true
  end

  #
  # Merges options in the info hash in a sane fashion, as some options
  # require special attention.
  #
  def merge_info(info, opts)
    opts.each_pair { |name, val|
      merge_check_key(info, name, val)
    }

    return info
  end

  #
  # Updates information in the supplied info hash and merges other
  # information.  This method is used to override things like Name, Version,
  # and Description without losing the ability to merge architectures,
  # platforms, and options.
  #
  def update_info(info, opts)
    opts.each_pair { |name, val|
      # If the supplied option name is one of the ones that we should
      # override by default
      if (UpdateableOptions.include?(name) == true)
        # Only if the entry is currently nil do we use our value
        if (info[name] == nil)
          info[name] = val
        end
      # Otherwise, perform the merge operation like normal
      else
        merge_check_key(info, name, val)
      end
    }

    return info
  end

  #
  # Checks and merges the supplied key/value pair in the supplied hash.
  #
  def merge_check_key(info, name, val)
    if (self.respond_to?("merge_info_#{name.downcase}"))
      eval("merge_info_#{name.downcase}(info, val)")
    else
      # If the info hash already has an entry for this name
      if (info[name])
        # If it's not an array, convert it to an array and merge the
        # two
        if (info[name].kind_of?(Array) == false)
          curr       = info[name]
          info[name] = [ curr ]
        end

        # If the value being merged is an array, add each one
        if (val.kind_of?(Array) == true)
          val.each { |v|
            if (info[name].include?(v) == false)
              info[name] << v
            end
          }
        # Otherwise just add the value
        elsif (info[name].include?(val) == false)
          info[name] << val
        end
      # Otherwise, just set the value equal if no current value
      # exists
      else
        info[name] = val
      end
    end
  end

  #
  # Merge aliases with an underscore delimiter.
  #
  def merge_info_alias(info, val)
    merge_info_string(info, 'Alias', val, '_')
  end

  #
  # Merges the module name.
  #
  def merge_info_name(info, val)
    merge_info_string(info, 'Name', val, ', ', true)
  end

  #
  # Merges the module description.
  #
  def merge_info_description(info, val)
    merge_info_string(info, 'Description', val)
  end

  #
  # Merge the module version.
  #
  def merge_info_version(info, val)
    merge_info_string(info, 'Version', val)
  end

  #
  # Merges a given key in the info hash with a delimiter.
  #
  def merge_info_string(info, key, val, delim = ', ', inverse = false)
    if (info[key])
      if (inverse == true)
        info[key] = info[key] + delim + val
      else
        info[key] = val + delim + info[key]
      end
    else
      info[key] = val
    end
  end

  #
  # Merges options.
  #
  def merge_info_options(info, val, advanced = false, evasion = false)

    key_name = ((advanced) ? 'Advanced' : (evasion) ? 'Evasion' : '') + 'Options'

    new_cont = OptionContainer.new
    new_cont.add_options(val, advanced, evasion)
    cur_cont = OptionContainer.new
    cur_cont.add_options(info[key_name] || [], advanced, evasion)

    new_cont.each_option { |name, option|
      next if (cur_cont.get(name))

      info[key_name]  = [] if (!info[key_name])
      info[key_name] << option
    }
  end

  #
  # Merges advanced options.
  #
  def merge_info_advanced_options(info, val)
    merge_info_options(info, val, true, false)
  end

  #
  # Merges advanced options.
  #
  def merge_info_evasion_options(info, val)
    merge_info_options(info, val, false, true)
  end

  attr_accessor :module_info # :nodoc:
  attr_writer   :references, :datastore, :options # :nodoc:
  attr_writer   :privileged # :nodoc:
  attr_writer   :license # :nodoc:

end

#
# Alias the data types so people can reference them just by Msf:: and not
# Msf::Module::
#
Author = Msf::Module::Author
Reference = Msf::Module::Reference

require 'msf/core/module/site_reference'
SiteReference = Msf::Module::SiteReference

Target = Msf::Module::Target

end

