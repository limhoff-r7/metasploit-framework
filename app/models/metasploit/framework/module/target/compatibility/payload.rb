class Metasploit::Framework::Module::Target::Compatibility::Payload < Metasploit::Framework::Compatibility::Payload
  #
  # CONSTANTS
  #

  # A list of preferred payloads in the best-first order
  DEFAULT_REFERENCE_NAMES = [
      'windows/meterpreter/reverse_tcp',
      'java/meterpreter/reverse_tcp',
      'php/meterpreter/reverse_tcp',
      'php/meterpreter_reverse_tcp',
      'ruby/shell_reverse_tcp',
      'cmd/unix/interact',
      'cmd/unix/reverse',
      'cmd/unix/reverse_perl',
      'cmd/unix/reverse_netcat_gaping',
      'windows/meterpreter/reverse_nonx_tcp',
      'windows/meterpreter/reverse_ord_tcp',
      'windows/shell/reverse_tcp',
      'generic/shell_reverse_tcp'
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
    each_compatible_instance.map(&:reference_name)
  end

  # @note Do not set :include_generics `true` inside of {Msf::Payload::Generic#actual_payload_instance} or it will
  #   cause a recursive loop of {Msf::Payload::Generic} trying to find the size of the generic payload which delegates
  #   to the actual payload, which is a generic payload, etc.
  #
  # @param options [Hash{Symbol => Boolean}]
  # @option options [Boolean] :include_generics (true) Set to `false` to exclude generic payloads.
  def each_compatible_cache_class(options={}, &block)
    options.assert_valid_keys(:include_generics)

    include_generics = options.fetch(:include_generics, true)

    compatible_cache_payload_instances = Mdm::Module::Instance.payloads_compatible_with(
        module_target
    )

    compatible_cache_classes = Mdm::Module::Class.where(
        id: compatible_cache_payload_instances.select(:module_class_id)
    )

    unless include_generics
      compatible_cache_classes = compatible_cache_classes.non_generic_payloads
    end

    unless reference_names.empty?
      compatible_cache_classes = compatible_cache_classes.where(reference_name: reference_names)
    end

    compatible_cache_classes.each(&block)
  end

  # Returns a list of compatible payloads based on architecture, platform, and size for {#target_model}.  Optionally,
  # restrict the searched set of payload modules to {#reference_names}.
  #
  # @param options (see #each_compatible_cache_class)
  # @return [Array<Msf::Payload>] payload instances that are compatible with this exploit.
  def each_compatible_instance(options={})
    unless block_given?
      enum_for(__method__, options)
    else
      super(options) do |payload_instance|
        if payload_instance_compatible?(payload_instance)
          yield payload_instance
        end
      end
    end
  end

  def exploit_instance
    if target_model
      target_model.metasploit_instance
    else
      nil
    end
  end

  undef_method :exploit_instance=

  delegate :framework,
           allow_nil: true,
           to: :exploit_instance

  delegate :module_target,
           # allow nil so validations can catch missing target_model instead of exceptions being raised.
           allow_nil: true,
           to: :target_model

  def module_manager
    if framework
      framework.modules
    else
      nil
    end
  end

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

    if !payload_space.nil? && actual_size > payload_space
      payload_class_location = module_class_location(payload_instance.class.module_class)

      dlog(
          "Skipping #{payload_class_location}: too big (#{actual_size} needed vs #{payload_space} available)"
      )
    elsif exploit_instance.compatible?(payload_instance)
      compatible = true
    end

    compatible
  end
end