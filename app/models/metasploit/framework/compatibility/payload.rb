# Base class for classes that determine {#each_compatible_instance} of {Msf::Payload} subclasses.
class Metasploit::Framework::Compatibility::Payload < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] exploit_instance
  #   The instance of {Msf::Exploit} that {#each_compatible_each} will be
  #   {Msf::Payload#exploit_instance associated with}.
  #
  #   @return [Msf::Payload]
  attr_accessor :exploit_instance

  #
  # Validations
  #

  validates :exploit_instance,
            presence: true

  #
  # Methods
  #

  # @abstract
  #
  # Yields `Mdm::Module::Class` with `Mdm::Module::Class#module_type` equal to `'payload'` that are compatible.
  #
  # @param options [Hash{Symbol => Boolean}]
  # @option options [Boolean] :include_generic (false) Whether to include generic payloads.
  # @yield [cache_payload_class]
  # @yieldparam cache_payload_class [Mdm::Module::Class] cache payload class to create in {#each_compatible_instance}.
  # @yieldreturn [void]
  # @return [void]
  def each_compatible_cache_class
    raise NotImplementedError
  end

  # Yields instances of compatible {Msf::Payload} subclasses created from {each_compatible_cache_class}.
  #
  # @param options (see #each_compatible_cache_class)
  # @yield [payload_instance]
  # @yieldparam payload_instance [Msf::Payload] an instance of an {Msf::Payload} subclass
  # @yieldreturn [void]
  # @return [void]
  def each_compatible_instance(options={})
    each_compatible_cache_class(options) { |cache_payload_class|
      payload_instance = module_manager.create_from_module_class(cache_payload_class)

      if payload_instance
        payload_instance.exploit_instance = exploit_instance

        yield payload_instance
      else
        payload_class_location = module_class_location(cache_payload_class)
        elog("Skipping #{payload_class_location}: failed to create instance")
      end
    }
  end

  def module_manager
    raise NotImplementedError
  end
end