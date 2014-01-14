class Metasploit::Framework::Module::Instance::Failure::Creation < Metasploit::Framework::Creation
  include Metasploit::Framework::Creation::Service

  #
  # Attributes
  #

  # @!attribute [rw] exploit_instance
  #   Instance of the {Msf::Exploit} that failed.
  #
  #   @return [Msf::Module]
  attr_accessor :exploit_instance

  #
  # Creation
  #

  create do
    creation = Metasploit::Framework::Attempt::Both::Creation.new(
        exploit_instance: exploit_instance,
        exploited: false,
        host: host,
        service: service
    )
    creation.valid!
    creation.create
  end

  #
  # Validation
  #

  validates :exploit_instance,
            presence: true
  validates :host,
            presence: true


  #
  # Methods
  #

  # @note Caller is responsible for saving the returned `Mdm::Host`.
  #
  # Finds or builds an `Mdm::Host` for {Msf::Module#workspace_record} with `exploit_instance.datastore['RHOST']` is
  # its `Mdm::Host#address`.
  #
  # @return [Mdm::Host] if `exploit_instance` has an 'RHOST' option and it is set.
  # @return [nil] otherwise
  def host
    unless instance_variable_defined? :@host
      @host = nil

      if exploit_instance
        if exploit_instance.options['RHOST']
          address = exploit_instance.datastore['RHOST']

          if address
            @host = exploit_instance.workspace_record.hosts.where(address: address).first_or_initialize
          end
        end
      end
    end

    @host
  end

  # The `Mdm::Module::Class` referencing {#exploit_instance #exploit_instance's} class.
  #
  # @return [Mdm::Module::Class]
  def module_class
    # cache because metasploit_class holds a weak reference only.
    @module_class ||= exploit_instance.class.module_class
  end
end