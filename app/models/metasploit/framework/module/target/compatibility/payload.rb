class Metasploit::Framework::Module::Target::Compatibility::Payload < Metasploit::Model::Base
  #
  # CONSTANTS
  #

  # A list of preferred payloads in the best-first order
  # @todo Fix derivation of payload names to strip payload_type prefix and strip handler_type from singles (MSP-2878)
  DEFAULT_REFERENCE_NAMES = [
      'stages/windows/meterpreter/reverse_tcp',
      'stages/java/meterpreter/reverse_tcp',
      'stages/php/meterpreter/reverse_tcp',
      'singles/php/meterpreter_reverse_tcp/reverse_tcp',
      'singles/ruby/shell_reverse_tcp/reverse_tcp',
      'singles/cmd/unix/interact/find_shell',
      'singles/cmd/unix/reverse/reverse_tcp_double',
      'singles/cmd/unix/reverse_perl/reverse_tcp',
      'singles/cmd/unix/reverse_netcat_gaping/reverse_tcp',
      'stages/windows/meterpreter/reverse_nonx_tcp',
      'stages/windows/meterpreter/reverse_ord_tcp',
      'stages/windows/shell/reverse_tcp',
      'singles/generic/shell_reverse_tcp/reverse_tcp'
  ].freeze

  #
  # Attributes
  #

  # @!attribute [rw] reference_names
  #   Array of `Mdm::Module::Class#reference_name` that are used to restrict the payload classes that are loaded
  #   and instantiated to check their {Msf::Payload#size} and {Msf::Module#compatible? compatibility} with this target
  #   and it's {Msf::Module::Target#metasploit_instance}.
  attr_writer :reference_names

  # @!attribute [rw] target_model
  #   The `Msf:Module::Target` whose compatible payloads to find.
  #
  #   @return [Msf::Module::Target]
  attr_accessor :target_model

  #
  # Validations
  #

  validates :module_target,
            presence: true
  validates :target_model,
            presence: true

  #
  # Methods
  #

  def compatible_class_reference_names
    compatible_instances.map(&:reference_name)
  end

  # Returns a list of compatible payloads based on architecture, platform, and size for {#target_model}.  Optionally,
  # restrict the searched set of payload modules to {#reference_names}.
  #
  # @return [Array<Msf::Payload>] payload instances that are compatible with this exploit.
  def compatible_instances
    compatible_cache_payload_instances = Mdm::Module::Instance.payloads_compatible_with(
        module_target
    ).includes(
        :module_class
    )

    unless reference_names.empty?
      compatible_cache_payload_instances = compatible_cache_payload_instances.where(
          Mdm::Module::Class.arel_table[:reference_name].in(reference_names)
      )
    end

    compatible_cache_payload_instances.each_with_object([]) { |cache_payload_instance, payload_instances|
      cache_payload_class = cache_payload_instance.module_class
      payload_instance = metasploit_instance.framework.modules.create_from_module_class(cache_payload_class)

      if payload_instance
        if payload_instance_compatible?(payload_instance)
          payload_instances << payload_instance
        end
      else
        payload_class_location = module_class_location(cache_payload_class)
        elog("Skipping #{payload_class_location}: failed to create instance")
      end
    }
  end

  delegate :metasploit_instance,
           :module_target,
           # allow nil so validations can catch missing target_model instead of exceptions being raised.
           allow_nil: true,
           to: :target_model

  def preferred_class_reference_name
    # do a Array#find on {#reference_names} so that order of {#reference_names} is
    # respected as compatible_default_class_reference_names order may not match.
    reference_names.find { |reference_name|
      compatible_class_reference_names.include?(reference_name)
    }
  end

  def reference_names
    @reference_names ||= DEFAULT_REFERENCE_NAMES
  end

  private

  def payload_instance_compatible?(payload_instance)
    compatible = false

    payload_space = target_model.payload_space
    actual_size = payload_instance.size

    if actual_size > payload_space
      payload_class_location = module_class_location(payload_instance.class.module_class)

      dlog(
          "Skipping #{payload_class_location}: too big (#{actual_size} needed vs #{payload_space} available)"
      )
    elsif metasploit_instance.compatible?(payload_instance)
      compatible = true
    end

    compatible
  end
end