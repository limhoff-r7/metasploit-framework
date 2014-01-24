module Msf::Module::Compatibility
  extend ActiveSupport::Concern

  module ClassMethods
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
    def normalize_module_info_compat!(module_info)
      module_info['Compat'] ||= {}
      compatibility = module_info['Compat']

      ['Encoder', 'Nop', 'Payload'].each do |module_type|
        # Initialize the module sub compatibilities
        compatibility[module_type] ||= {}

        module_type_compatibility = module_info["#{module_type}Compat"]
        module_type_compatibility ||= {}

        # Update the compat-derived module specific compatibilities from
        # the specific ones to make a uniform view of compatibilities
        compatibility[module_type].update(module_type_compatibility)
      end
    end
  end

  #
  # Instance Methods
  #

  # Returns the hash that describes this module's compatibilities.
  #
  def compat
    module_info['Compat'] || {}
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
end