# -*- coding: binary -*-
require 'msf/core'

###
#
# The generic payloads are used to define a generalized payload type that
# is both architecture and platform independent.  Under the hood, generic
# payloads seek out the correct payload for the appropriate architecture
# and platform that is being targeted.
#
###
module Msf::Payload::Generic
  #
  # Attributes
  #

  # @!attribute [rw] actual_payload_instance
  #   Instance of {Msf::Payload} subclass to which this should delegate.
  #
  #   @return [Msf::Payload]
  attr_writer :actual_payload_instance

  # @!attribute [rw] explicit_architecture_abbreviations
  #   Makes it possible to define an explicit architecture.  This is used for things like payload regeneration.
  #
  #   @return [String, Array<String>]
  attr_accessor :explicit_architecture_abbreviations

  # @!attribute [rw] explicit_platform_list
  #  Makes it possible to define an explicit platform.  This is used for things like payload regeneration.
  #
  #  @return [String, Msf::Module::PlatformList]
  attr_accessor :explicit_platform_list

  #
  # Methods
  #

  # Finds actual payload instance that
  # @return [Msf::Payload] a non-generic payload
  def actual_payload_instance
    unless @actual_payload_instance
      compatibility_methods = [:exploit_compatibility, :generic_compatibility]

      compatibility_methods.each do |compatibility_method|
        compatibility = send(compatibility_method)

        if compatibility
          @actual_payload_instance = compatibility.each_compatible_instance.first

          if @actual_payload_instance
            break
          end
        end
      end

      unless @actual_payload_instance
        architecture_abbreviations = actual_architecture_abbreviations
        architecture_count = architecture_abbreviations.length
        architecture_pluralization = 'architecture'.pluralize(architecture_count)
        architecture_sentence = architecture_abbreviations.to_sentence

        platform_fully_qualified_names = actual_platform_list.platforms.map(&:fully_qualified_name)
        platform_count = platform_fully_qualified_names.length
        platform_pluralization = 'platform'.pluralize(platform_count)
        platform_sentence = platform_fully_qualified_names.to_sentence

        raise Msf::NoCompatiblePayloadError,
              "Could not locate a compatible payload for #{architecture_pluralization} (#{architecture_sentence}) " \
              "and #{platform_pluralization} (#{platform_sentence})"
      else
        actual_payload_class_location = module_class_location(@actual_payload_instance.class.module_class)
        generic_module_class_location = module_class_location(self.class.module_class)
        dlog(
            "Selected payload (#{actual_payload_class_location}) " \
            "from generic payload (#{generic_module_class_location})",
            'core',
            LEV_2
        )
        # Share our datastore with the actual payload so that it has the
        # appropriate values to substitute ad so on.
        @actual_payload_instance.share_data_store(self.data_store)

        # Set the associated exploit for the payload.
        @actual_payload_instance.exploit_instance  = self.exploit_instance

        # Set the parent payload to this payload so that we can handle
        # things like session creation (so that event notifications will
        # work properly)
        @actual_payload_instance.parent_payload = self

        # Set the cached user_input/user_output
        @actual_payload_instance.user_input  = self.user_input
        @actual_payload_instance.user_output = self.user_output
      end
    end

    @actual_payload_instance
  end

  def generic_compatibility
    generic_compatibility = Metasploit::Framework::Module::Instance::Payload::Generic::Compatibility::Payload.new(
        compatibility_options.merge(
            parent: actual_compatibility
        )
    )
    generic_compatibility.valid!

    generic_compatibility
  end

  # @note Generate is different from other methods -- it will try to re-detect
  #    the actual payload in case settings have changed.  Other methods will
  #    use the cached version if possible.
  #
  # Generates raw payload.
  #
  # @return [void]
  def generate
    reset

    actual_payload_instance.generate
  end

  #
  # Registers options that are common to all generic payloads, such as
  # platform and arch.
  #
  def initialize(info = {})
    super(
        Msf::Module::ModuleInfo.merge!(
            info,
            'Arch'     => ARCH_ALL - [ARCH_TTY],
            'Platform' => ''
        )
    )

    register_advanced_options(
      [
        Msf::OptString.new('PLATFORM',
          [
            false,
            "The platform that is being targeted",
            nil
          ]),
        Msf::OptString.new('ARCH',
          [
            false,
            "The architecture that is being targeted",
            nil
          ])
      ], Msf::Payload::Generic)
  end

  #
  # Overrides -- we have to redirect all potential payload methods
  # to the actual payload so that they get handled appropriately, cuz
  # we're like a proxy and stuff.  We can't use method_undefined
  # because all of these methods are actually defined.
  #

  delegate :compatible_cache_encoder_instances,
           :compatible_cache_nop_instances,
           :generate_stage,
           :handle_connection,
           :handle_connection_stage,
           :handle_intermediate_stage,
           :offset_relative_address_and_type_by_name,
           :on_session,
           :payload,
           :replace_var,
           :stage_offset_relative_address_and_type_by_name,
           :stage_over_connection?,
           :stage_prefix,
           :stage_prefix=,
           :stage_payload,
           :stager_offsets,
           :stager_payload,
           :substitute_vars,
           to: :actual_payload_instance

  #
  # Reset's the generic payload's internal state so that it can find a new
  # actual payload.
  #
  def reset
    self.explicit_architecture_abbreviations     = nil
    self.explicit_platform_list = nil
    self.actual_payload_instance = nil
  end

  #
  # Stager overrides
  #

  def user_input=(h)
    @user_input = h
    actual_payload_instance.user_input = h
  end

  def user_output=(h)
    @user_output = h
    actual_payload_instance.user_output = h
  end

  private

  # Returns the actual architecture abbreviations that should be used for the payload.
  #
  # @return [Array<String>] Array of `Metasploit::Model::Architecture#abbreviation`s.
  def actual_architecture_abbreviations
    architecture_abbreviations = nil

    if explicit_architecture_abbreviations.nil? == false
      architecture_abbreviations = explicit_architecture_abbreviations
    elsif data_store['ARCH']
      architecture_abbreviations = data_store['ARCH']
    elsif exploit_instance
      architecture_abbreviations = exploit_instance.target_architecture_abbreviations || ARCH_X86
    end

    # If we still have an invalid architecture, then we suck.
    if architecture_abbreviations.nil?
      raise Msf::NoCompatiblePayloadError, "An architecture could not be determined by the generic payload"
    elsif architecture_abbreviations.kind_of?(String)
      architecture_abbreviations = [ architecture_abbreviations ]
    end

    architecture_abbreviations
  end

  def actual_compatibility
    unless instance_variable_defined? :@actual_compatibility
      platform_fully_qualified_names = actual_platform_list.platforms.map(&:fully_qualified_name)
      actual_compatibility = Metasploit::Framework::Module::Instance::Payload::Actual::Compatibility::Payload.new(
          architecture_abbreviations: actual_architecture_abbreviations,
          exploit_instance: exploit_instance,
          platform_fully_qualified_names: platform_fully_qualified_names,
          universal_module_instance_creator: framework.modules
      )
      actual_compatibility.valid!

      @actual_compatibility = actual_compatibility
    end

    @actual_compatibility
  end

  # Returns the actual platform list that should be used for the payload.
  #
  # @return [Msf::Module::PlatformList]
  def actual_platform_list
    platform_list = nil

    if explicit_platform_list.nil? == false
      platform_list = explicit_platform_list
    elsif data_store['PLATFORM']
      platform_list = data_store['PLATFORM']
    elsif exploit_instance
      platform_list = exploit_instance.target_platform_list
    end

    # If we still have an invalid platform, then we suck.
    if platform_list.nil?
      raise Msf::NoCompatiblePayloadError, "A platform could not be determined by the generic payload"
    elsif platform_list.kind_of?(String)
      platform_list = Msf::Module::PlatformList.transform(platform_list)
    end

    platform_list
  end

  def compatibility_options
    @compatibility_options ||= {
        handler_module: self.class.ancestor_handler_module,
        payload_type: self.class.module_class.payload_type,
        session_class: session_class
    }
  end

  def exploit_compatibility
    exploit_compatibility = nil

    if exploit_instance
      exploit_compatibility = Metasploit::Framework::Module::Instance::Payload::Generic::Compatibility::Payload.new(
          compatibility_options.merge(
              parent: exploit_instance.payload_compatibility
          )
      )
      exploit_compatibility.valid!
    end

    exploit_compatibility
  end
end
