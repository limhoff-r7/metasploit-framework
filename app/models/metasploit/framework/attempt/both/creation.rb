# Creates both an `Mdm::ExploitAttempt` and an `Mdm::VulnAttempt`.
class Metasploit::Framework::Attempt::Both::Creation < Metasploit::Framework::Attempt::Creation::Base
  #
  # Attributes
  #

  # @!attribute [rw] host
  #   The host that is vulnerable and on which an exploit was attempted.
  #
  #   @return [Mdm::Host]
  attr_accessor :host

  # @!attribute [rw] service
  #   The service that is vulnerable and on which an exploit was attempted.
  #
  #   @return [Mdm::Service, nil]
  attr_accessor :service

  #
  # Creation
  #

  create do
    attempt_attributes = {
        attempted_at: attempted_at,
        cache_exploit_class: cache_exploit_class,
        exploit_instance: exploit_instance,
        exploited: exploited?,
        vuln: vuln
    }

    creations = []
    creations << Metasploit::Framework::Attempt::Exploit::Creation.new(
        attempt_attributes.merge(
            host: host,
            service: service
        )
    )
    creations << Metasploit::Framework::Attempt::Vuln::Creation.new(
        attempt_attributes
    )

    creations.each do |creation|
      creation.valid!
      creation.create
    end
  end

  #
  # Method
  #

  def vuln
    unless instance_variable_defined? :@vuln
      synchronization = Metasploit::Framework::Vuln::Synchronization.new(
          host: host,
          source: cache_exploit_class.module_instance,
          service: service
      )
      synchronization.valid!
      synchronization.synchronize

      @vuln = synchronization.vuln
    end

    @vuln
  end
end