# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/module/save_registers'
require 'metasm'
require 'metasploit/framework/deprecation'

module Msf

###
#
# This class represents the base class for a logical payload.  The framework
# automatically generates payload combinations at runtime which are all
# extended for this Payload as a base class.
#
###
class Payload < Msf::Module
  extend Metasploit::Framework::Module::Class::Handler

  self.module_type = Metasploit::Model::Module::Type::PAYLOAD

  require 'rex/payloads'

  require 'msf/core/payload/single'
  require 'msf/core/payload/generic'
  require 'msf/core/payload/stager'
  require 'msf/core/payload/type'

  # Platform specific includes
  require 'msf/core/payload/aix'
  require 'msf/core/payload/bsd'
  require 'msf/core/payload/linux'
  require 'msf/core/payload/osx'
  require 'msf/core/payload/solaris'
  require 'msf/core/payload/windows'
  require 'msf/core/payload/netware'
  require 'msf/core/payload/java'
  require 'msf/core/payload/dalvik'
  require 'msf/core/payload/firefox'

  include Msf::Module::SaveRegisters

  #
  # Creates an instance of a payload module using the supplied information.
  #
  def initialize(info = {})
    merged_info = info.merge(
        # used for compatibility filtering purposes.
        'ConnectionType' => self.class.connection_type
    )

    super(merged_info)

    # If this is a staged payload but there is no stage information,
    # then this is actually a stager + single combination.  Set up the
    # information hash accordingly.
    if self.class.include?(Msf::Payload::Single) and
      self.class.include?(Msf::Payload::Stager)
      self.module_info['Stage'] = {}

      if self.module_info['Payload']
        self.module_info['Stage']['Payload']  = self.module_info['Payload']['Payload'] || ""
        self.module_info['Stage']['Assembly'] = self.module_info['Payload']['Assembly'] || ""
        self.module_info['Stage']['Offsets']  = self.module_info['Payload']['Offsets'] || {}
      else
        self.module_info['Stage']['Payload']  = ""
        self.module_info['Stage']['Assembly'] = ""
        self.module_info['Stage']['Offsets']  = {}
      end

      @staged = true
    else
      @staged = false
    end
  end

  ##
  #
  # Accessors
  #
  ##

  #
  # Returns the string of bad characters for this payload, if any.
  #
  def badchars
    return self.module_info['BadChars']
  end

  #
  # Returns the type of payload, either single or staged.  Stage is
  # the default because singles and stagers are encouraged to include
  # the Single and Stager mixin which override the payload_type.
  #
  def payload_type
    return Type::Stage
  end

  #
  # Returns the string version of the payload type
  #
  def payload_type_s
    case payload_type
      when Type::Stage
        return "stage"
      when Type::Stager
        return "stager"
      when Type::Single
        return "single"
      else
        return "unknown"
    end
  end

  #
  # This method returns whether or not this payload uses staging.
  #
  def staged?
    (@staged or payload_type == Type::Stager or payload_type == Type::Stage)
  end

  #
  # Returns the payload's size.  If the payload is staged, the size of the
  # first stage is returned.
  #
  def size
    pl = nil
    begin
      pl = generate()
    rescue NoCompatiblePayloadError
    end
    pl ||= ''
    pl.length
  end

  #
  # Returns the raw payload that has not had variable substitution occur.
  #
  def payload
    return module_info['Payload'] ? module_info['Payload']['Payload'] : nil
  end

  #
  # Returns the assembly string that describes the payload if one exists.
  #
  def assembly
    return module_info['Payload'] ? module_info['Payload']['Assembly'] : nil
  end

  #
  # Sets the assembly string that describes the payload
  # If this method is used to define the payload, a payload with no offsets will be created
  #
  def assembly=(asm)
    module_info['Payload'] ||= {'Offsets' => {} }
    module_info['Payload']['Assembly'] = asm
  end

  #
  # Returns the offsets to variables that must be substitute, if any.
  #
  def offset_relative_address_and_type_by_name
    return module_info['Payload'] ? module_info['Payload']['Offsets'] : nil
  end

  #
  # Returns the staging convention that the payload uses, if any.  This is
  # used to make sure that only compatible stagers and stages are built
  # (where assumptions are made about register/environment initialization
  # state and hand-off).
  #
  def convention
    module_info['Convention']
  end

  #
  # Returns the module's connection type, such as reverse, bind, noconn,
  # or whatever else the case may be.
  #
  def self.connection_type
    ancestor_handler_module.general_handler_type
  end

  #
  # Returns the method used by the payload to resolve symbols for the purpose
  # of calling functions, such as ws2ord.
  #
  def symbol_lookup
    module_info['SymbolLookup']
  end

  #
  # Checks to see if the supplied convention is compatible with this
  # payload's convention.
  #
  def compatible_convention?(conv)
    # If we ourself don't have a convention or our convention is equal to
    # the one supplied, then we know we are compatible.
    if ((self.convention == nil) or
        (self.convention == conv))
      true
    # On the flip side, if we are a stager and the supplied convention is
    # nil, then we know it's compatible.
    elsif ((payload_type == Type::Stager) and
           (conv == nil))
      true
    # Otherwise, the conventions don't match in some way or another, and as
    # such we deem ourself as not being compatible with the supplied
    # convention.
    else
      false
    end
  end

  # @!method session
  #   (see #session_class)
  #   @deprecated Use {#session_class}
  Metasploit::Framework::Deprecation.rename_methods(self, session: :session_class)

  # The session class that is associated with this payload and will
  # be used to create a session as necessary.
  #
  # @return [Class<Msf::Session>]
  def session_class
    module_info['Session']
  end

  ##
  #
  # Generation & variable substitution
  #
  ##

  #
  # Generates the payload and returns the raw buffer to the caller.
  #
  def generate
    internal_generate
  end

  #
  # Substitutes variables with values from the module's {Msf::Module::DataStore#data_store} in the
  # supplied raw buffer for a given set of named offsets.  For instance,
  # RHOST is substituted with the RHOST value from the {Msf::Module::DataStore#data_store} which will
  # have been populated by the framework.
  #
  # Supprted packing types:
  #
  # - ADDR  (foo.com, 1.2.3.4)
  # - ADDR6 (foo.com, fe80::1234:5678:8910:1234)
  # - ADDR16MSB, ADD16LSB, ADDR22MSB, ADD22LSB (foo.com, 1.2.3.4)
  #   Advanced packing types for 16/16 and 22/10 bits substitution. The 16
  #   bits types uses two offsets indicating where the 16 bits pair will be
  #   substituted, while the 22 bits types uses two offsets indicating the
  #   instructions where the 22/10 bits pair will be substituted. Normally
  #   these are offsets to "sethi" and "or" instructions on SPARC architecture.
  # - HEX   (0x12345678, "\x41\x42\x43\x44")
  # - RAW   (raw bytes)
  #
  def substitute_vars(raw, offsets)
    offsets.each_pair { |name, info|
      offset, pack = info

      # Give the derived class a chance to substitute this variable
      next if (replace_var(raw, name, offset, pack) == true)

      # Now it's our turn...
      if ((val = data_store[name]))
        if (pack == 'ADDR')
          val = Rex::Socket.resolv_nbo(val)

          # Someone gave us a funky address (ipv6?)
          if(val.length == 16)
            raise RuntimeError, "IPv6 address specified for IPv4 payload."
          end
        elsif (pack == 'ADDR6')
          val = Rex::Socket.resolv_nbo(val)

          # Convert v4 to the v6ish address
          if(val.length == 4)
            nip = "fe80::5efe:" + val.unpack("C*").join(".")
            val = Rex::Socket.resolv_nbo(nip)
          end
        elsif (['ADDR16MSB', 'ADDR16LSB', 'ADDR22MSB', 'ADDR22LSB'].include?(pack))
          val = Rex::Socket.resolv_nbo(val)

          # Someone gave us a funky address (ipv6?)
          if(val.length == 16)
            raise RuntimeError, "IPv6 address specified for IPv4 payload."
          end
        elsif (pack == 'RAW')
          # Just use the raw value...
        else
          # Check to see if the value is a hex string.  If so, convert
          # it.
          if val.kind_of?(String)
            if val =~ /^\\x/n
              val = [ val.gsub(/\\x/n, '') ].pack("H*").unpack(pack)[0]
            elsif val =~ /^0x/n
              val = val.hex
            end
          end

          # NOTE:
          # Packing assumes integer format at this point, should fix...
          val = [ val.to_i ].pack(pack)
        end

        # Substitute it
        if (['ADDR16MSB', 'ADDR16LSB'].include?(pack))
          if (offset.length != 2)
            raise RuntimeError, "Missing value for payload offset, there must be two offsets."
          end

          if (pack == 'ADDR16LSB')
            val = val.unpack('N').pack('V')
          end

          raw[offset[0], 2] = val[0, 2]
          raw[offset[1], 2] = val[2, 2]

        elsif (['ADDR22MSB', 'ADDR22LSB'].include?(pack))
          if (offset.length != 2)
            raise RuntimeError, "Missing value for payload offset, there must be two offsets."
          end

          if (pack == 'ADDR22LSB')
            val = val.unpack('N').pack('V')
          end

          hi = (0xfffffc00 & val) >> 10
          lo = 0x3ff & val

          ins = raw[offset[0], 4]
          raw[offset[0], 4] = ins | hi

          ins = raw[offset[1], 4]
          raw[offset[1], 4] = ins | lo

        else
          raw[offset, val.length] = val

        end
      else
        wlog("Missing value for payload offset #{name}, skipping.",
          'core', LEV_3)
      end
    }
  end

  #
  # Replaces an individual variable in the supplied buffer at an offset
  # using the given pack type.  This is here to allow derived payloads
  # the opportunity to replace advanced variables.
  #
  def replace_var(raw, name, offset, pack)
    return false
  end

  ##
  #
  # Shortcut methods for filtering compatible encoders
  # and NOP sleds
  #
  ##

  # `Mdm::Module::Instances` that are encoders and share at least 1 `Mdm::Architecture` with this payload.
  #
  # @return [ActiveRecord::Relation<Mdm::Module::Instance>]
  def compatible_cache_encoder_instances
    Mdm::Module::Instance.encoders_compatible_with(module_instance)
  end

  # `Mdm::Module::Instances` that are nops and share at least 1 `Mdm::Architecture` with this payload.
  #
  # @return [ActiveRecord::Relation<Mdm::Module::Instance>]
  def compatible_cache_nop_instances
    Mdm::Module::Instance.nops_compatible_with(module_instance)
  end

  # All the {Msf::Nop} from {#compatible_cache_nop_instances}.
  #
  # @return [Metasploit::Framework::Module::Instance::Enumerator<Msf::Nop>]
  def compatible_nop_instances
    cache_module_classes = Mdm::Module::Class.with_module_instances(
        compatible_cache_nop_instances
    ).ranked
    enumerator = Metasploit::Framework::Module::Instance::Enumerator.new(
        cache_module_classes: cache_module_classes,
        module_manager: framework.modules

    )
    enumerator.valid!

    enumerator
  end

  ##
  #
  # Event notifications.
  #
  ##

  # @note `session` will not have a {Msf::Session#sid} until it is registered.
  #
  # Called before {Msf::SessionManager#register} in order to allow payload and/or handler to set session attributes
  # before it is registered with the framework and the `Mdm::Session` is created in the database.
  #
  # @param session [Msf::Session] an unregistered session
  def before_register_session(session)
  end

  #
  # Once an exploit completes and a session has been created on behalf of the
  # payload, the framework will call the payload's on_session notification
  # routine to allow it to manipulate the session prior to handing off
  # control to the user.
  #
  def on_session(session)


    # If this payload is associated with an exploit, inform the exploit
    # that a session has been created and potentially shut down any
    # open sockets. This allows active exploits to continue hammering
    # on a service until a session is created.
    if exploit_instance
      # Signal that a new session is created by calling the exploit's
      # on_new_session handler. The default behavior is to set an
      # instance variable, which the exploit will have to check.
      begin
        exploit_instance.on_new_session(session)
      rescue ::Exception => exception
        dlog("#{exploit_instance.full_name}: #{exception.class} #{exception}:\n#{exception.backtrace.join("\n")}", 'core', LEV_1)
      end

      # Set the abort sockets flag only if the exploit is not passive
      # and the connection type is not 'find'
      if (
        (exploit_instance.exploit_type == Exploit::Type::Remote) and
        (!exploit_instance.passive?) and
        (self.class.connection_type != 'find')
         )
         exploit_instance.abort_sockets
      end

    end

  end

  #
  # This attribute holds the string that should be prepended to the buffer
  # when it's generated.
  #
  attr_accessor :prepend
  #
  # This attribute holds the string that should be appended to the buffer
  # when it's generated.
  #
  attr_accessor :append
  #
  # This attribute holds the string that should be prepended to the encoded
  # version of the payload (in front of the encoder as well).
  #
  attr_accessor :prepend_encoder

  #
  # If this payload is associated with an exploit, the exploit_instance
  # attribute will point to that exploit instance.
  #
  attr_accessor :exploit_instance

protected

  #
  # If the payload has assembly that needs to be compiled, do so now.
  #
  # Blobs will be cached in the framework's PayloadSet
  #
  # @see PayloadSet#check_blob_cache
  # @param assembly [String] Assembly code to be assembled into a raw payload
  # @param offset_relative_address_and_type_by_name [Hash{String => Array<(Integer, String)>}]
  # @return (see Metasploit::Framework::Payload::Assemble)
  # @raise ArgumentError if `asm` is blank.
  def assemble(assembly, offset_relative_address_and_type_by_name={})
    assemble = Metasploit::Framework::Payload::Assemble.new(
        assembly: assembly,
        offset_relative_address_and_type_by_name: offset_relative_address_and_type_by_name,
        payload_instance: self
    )
    assemble.valid!

    assemble.assembled
  end

  #
  # Generate the payload using our local payload blob and offsets
  #
  def internal_generate
    # Build the payload, either by using the raw payload blob defined in the
    # module or by actually assembling it
    if assembly.present?
      assembled = assemble(assembly, offset_relative_address_and_type_by_name)
    else
      assembled = Metasploit::Framework::Payload::Assembled.new(
          data: payload,
          offset_relative_address_and_type_by_name: offset_relative_address_and_type_by_name
      )
      assembled.valid!
    end

    # MUST dup because {Msf::Payload#substitute_vars} will mutate the String passed to it.
    generated = assembled.data.dup
    substitute_vars(generated, assembled.offset_relative_address_and_type_by_name)

    generated
  end

  ##
  #
  # Custom merge operations for payloads
  #
  ##

  #
  # Merge the name to prefix the existing one and separate them
  # with a comma
  #
  def merge_name(info, val)
    if (info['Name'])
      info['Name'] = val + ',' + info['Name']
    else
      info['Name'] = val
    end
  end

end

end
