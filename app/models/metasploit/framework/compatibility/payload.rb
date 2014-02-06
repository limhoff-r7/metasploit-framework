# Base class for classes that determine {#each_compatible_instance} of {Msf::Payload} subclasses.
class Metasploit::Framework::Compatibility::Payload < Metasploit::Model::Base
  include Metasploit::Framework::Module::Class::Logging

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
        connect_exploit_instance(payload_instance)

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

  private

  # Connects the `payload_instance` to {#exploit_instance}, including the {Msf::Module#data_store}.
  #
  # @param payload_instance [Msf::Payload] a payload that is about to be returned by {#each_compatible_instance} that
  #   needs its {Msf::Payload#exploit_instance} set and {Msf::Module#data_store} populated so it can
  #   {Msf::Payload#generate} and find its {Msf::Payload#size}.
  #
  # @return [void]
  def connect_exploit_instance(payload_instance)
    payload_instance.exploit_instance = exploit_instance

    # Include exploit_instance's data_store in payload_instance so that fields set on the exploit, like LHOST are
    # available to the payload when it generates to find its size.
    #
    # CANNOT use Msf::Module#share_data_store because the options from payload_instance will be imported into
    # exploit_instance's data_store, which means that all previous, incompatible payload_instance's options and
    # their defaults will be in the data_store (potentially) leading to the wrong default being used for the final
    # compatible payload_instance.
    payload_instance.data_store.merge!(exploit_instance.data_store)

    unless payload_instance.data_store['LHOST']
      hosts = Metasploit::Framework::Module::Instance::Hosts.new(metasploit_instance: exploit_instance)
      hosts.valid!

      payload_instance.data_store['LHOST'] = hosts.local
    end
  end
end