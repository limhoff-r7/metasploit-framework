require 'ice_nine'

module Msf::Module::ModuleInfo
  #
  # CONSTANTS
  #

  # Defaults for {#module_info}.
  DEFAULT_MODULE_INFO = IceNine.deep_freeze(
      'Name'        => nil,
      'Description' => nil,
      'Version'     => '0',
      'Author'      => nil,
      'Arch'        => nil, # No architectures by default.
      'Platform'    => [],  # No platforms by default.
      'Ref'         => nil,
      'Privileged'  => false,
      'License'     => MSF_LICENSE
  )

  # The list of options that support merging in an information hash.
  #
  UPDATABLE_MODULE_INFO_KEYS = [
      "Alias",
      "Description",
      "Name",
      "PayloadCompat"
  ]

  #
  # Module Methods
  #

  # Merges options in the info hash in a sane fashion, as some options
  # require special attention.
  #
  # @return [Hash] `current`
  def self.merge!(current, updates={})
    updates.each_pair { |name, val|
      merge_check_key!(current, name, val)
    }

    current
  end

  # Merges advanced options.
  #
  def self.merge_advanced_options!(info, val)
    merge_options!(info, val, true, false)
  end

  # Merge aliases with an underscore delimiter.
  #
  def self.merge_alias!(info, val)
    merge_string!(info, 'Alias', val, '_')
  end

  # Merges the module description.
  #
  def self.merge_description!(info, val)
    merge_string!(info, 'Description', val)
  end

  # Merges advanced options.
  #
  def self.merge_evasion_options!(info, val)
    merge_options!(info, val, false, true)
  end

  # Merges the module name.
  #
  def self.merge_name!(info, val)
    merge_string!(info, 'Name', val, ', ', true)
  end

  # Checks and merges the supplied key/value pair in the supplied hash.
  #
  def self.merge_check_key!(module_info, key, new_value)
    key_method = "merge_#{key.downcase}!"

    if respond_to? key_method
      send key_method, module_info, new_value
    else
      current_value = module_info[key]

      # If the info hash already has an entry for this name
      if (current_value)
        # If it's not an array, convert it to an array and merge the
        # two
        module_info[key] = Array.wrap(current_value)
        current_value = module_info[key]
        new_value = Array.wrap(new_value)

        # If the value being merged is an array, add each one
        new_value.each { |new_element|
          unless current_value.include? new_element
            current_value << new_element
          end
        }
      # Otherwise, just set the value equal if no current value
      # exists
      else
        module_info[key] = new_value
      end
    end
  end

  # Merges options.
  #
  def self.merge_options!(info, val, advanced = false, evasion = false)
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

  # Merges a given key in the info hash with a delimiter.
  #
  def self.merge_string!(info, key, val, delim = ', ', inverse = false)
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

  # Merge the module version.
  #
  def self.merge_version!(info, val)
    merge_string!(info, 'Version', val)
  end

  # Updates information in the supplied info hash and merges other
  # information.  This method is used to override things like Name, Version,
  # and Description without losing the ability to merge architectures,
  # platforms, and options.
  #
  # @return [Hash] `current`
  def self.update!(current, updates={})
    updates.each_pair { |name, val|
      # If the supplied option name is one of the ones that we should
      # override by default
      if UPDATABLE_MODULE_INFO_KEYS.include?(name)
        # Only if the entry is currently nil do we use our value
        if current[name].nil?
          current[name] = val
        end
      # Otherwise, perform the merge operation like normal
      else
        merge_check_key!(current, name, val)
      end
    }

    current
  end

  #
  # Instance Methods
  #

  # (see Msf::Module::ModuleInfo.merge!)
  # @deprecated Use {Msf::Module::ModuleInfo.merge!}
  def merge_info(info, opts={})
    ActiveSupport::Deprecation.warn "#{self.class}##{__method__} is deprecated.  Use Msf::Module::ModuleInfo.merge! instead"
    Msf::Module::ModuleInfo.merge!(info, opts)
  end

  def module_info
    @module_info ||= DEFAULT_MODULE_INFO
  end

  # Set {#module_info} to a deep frozen duplicate of `module_info`.
  #
  # @param module_info [Hash]
  # @return [Hash]
  def module_info=(module_info)
    normalized_module_info = DEFAULT_MODULE_INFO.merge(module_info)

    self.class.normalize_module_info_compat!(normalized_module_info)

    @module_info = IceNine.deep_freeze(normalized_module_info)
  end

  # (see Msf::Module::ModuleInfo.update!)
  # @deprecated Use {Msf::Module::ModuleInfo.update!}.
  def update_info(info, opts)
    ActiveSupport::Deprecation.warn "#{self.class}##{__method__} is deprecated.  Use Msf::Module::ModuleInfo.update! instead"
    Msf::Module::ModuleInfo.update!(info, opts)
  end
end