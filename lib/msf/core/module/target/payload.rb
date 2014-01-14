# Target-specific payload modifications
module Msf::Module::Target::Payload
  # Returns a list of compatible payload instances based on architecture, platform, and space/size for this target.
  # Optionally, restrict the search set of payload module classes to a given set of
  # `Mdm::Module::Class#reference_names`.
  #
  # @param options [Hash{Symbol => Array<String>}]
  # @option options [Array<String>] :reference_names Array of `Mdm::Module::Class#reference_name` for payloads from
  #   which to return compatible payloads.
  # @return [Array<Msf::Payload>]  payload instances that are compatible with this target.
  def compatible_payload_instances(options={})
    options.assert_valid_keys(:reference_names)

    payload_compatibility = self.payload_compatibility(refrence_names: options[:reference_names])

    payload_compatibility.instances
  end

  def declared_payload_space
    unless instance_variable_defined? :@declared_payload_space
      @declared_payload_space = nil
      payload = opts['Payload']

      if payload
        payload_space = payload['Space']

        if payload_space
          @declared_payload_space = payload_space.to_i
        end
      end
    end

    @declared_payload_space
  end

  # @param options [Hash{Symbol => Array<String>}]
  # @option options [Array<String>] :reference_names Array of `Mdm::Module::Class#reference_name` for payloads from
  #   which to return compatible payloads.
  # @return [Metasploit::Framework::Module::Target::Compatibility::Payload]
  def payload_compatibility(options={})
    options.assert_valid_keys(:reference_names)

    payload_compatibility = Metasploit::Framework::Module::Target::Compatibility::Payload.new(
        reference_names: options[:reference_names],
        target_model: self
    )
    payload_compatibility.valid!

    payload_compatibility
  end

  #
  # The bad characters specific to this target for the payload.
  #
  def payload_badchars
    opts['Payload'] ? opts['Payload']['BadChars'] : nil
  end

  #
  # Payload prepend information for this target.
  #
  def payload_prepend
    opts['Payload'] ? opts['Payload']['Prepend'] : nil
  end

  #
  # Payload append information for this target.
  #
  def payload_append
    opts['Payload'] ? opts['Payload']['Append'] : nil
  end

  #
  # Payload prepend encoder information for this target.
  #
  def payload_prepend_encoder
    opts['Payload'] ? opts['Payload']['PrependEncoder'] : nil
  end

  #
  # Payload stack adjustment information for this target.
  #
  def payload_stack_adjustment
    opts['Payload'] ? opts['Payload']['StackAdjustment'] : nil
  end

  #
  # Payload max nops information for this target.
  #
  def payload_max_nops
    opts['Payload'] ? opts['Payload']['MaxNops'] : nil
  end

  #
  # Payload min nops information for this target.
  #
  def payload_min_nops
    opts['Payload'] ? opts['Payload']['MinNops'] : nil
  end

  #
  # Payload space information for this target.
  #
  def payload_space
    declared_payload_space || metasploit_instance.payload_space
  end

  #
  # The payload encoder type or types that can be used when generating the
  # encoded payload (such as alphanum, unicode, xor, and so on).
  #
  def payload_encoder_type
    opts['Payload'] ? opts['Payload']['EncoderType'] : nil
  end

  #
  # A hash of options that be initialized in the select encoder's datastore
  # that may be required as parameters for the encoding operation.  This is
  # particularly useful when a specific encoder type is being used (as
  # specified by the EncoderType hash element).
  #
  def payload_encoder_options
    opts['Payload'] ? opts['Payload']['EncoderOptions'] : nil
  end

  #
  # Returns a hash of extended options that are applicable to payloads used
  # against this particular target.
  #
  def payload_extended_options
    opts['Payload'] ? opts['Payload']['ExtendedOptions'] : nil
  end
end