# Creates or retrieves an `Mdm::Vuln` for a {#host}, {#service}, and {#source}.
class Metasploit::Framework::Vuln::Synchronization < Metasploit::Framework::Synchronization::Base
  #
  # Attributes
  #

  # @!attribute [rw] host
  #   The host that is vulnerable.
  #
  #   @return [Mdm::Host]
  attr_accessor :host

  # @!attribute [rw] service
  #   The service that is vulnerable.
  #
  #   @return [Mdm::Service]
  attr_accessor :service

  # @!attribute [rw] source
  #    The module instance that triggered this vulnerability and whose
  #    `Mdm::Module::Instance#name` and `Mdm::Module::Instance#references` to copy to {#vuln}.
  #
  #    @return [Mdm::Module::Instance]

  # @!attribute [rw] vuln
  #
  #   @return [Mdm::Vuln]
  attr_reader :vuln

  #
  # Synchronization
  #

  synchronize do
    @vuln ||= preexisting_vuln
    @vuln ||= created_vuln
  end

  #
  # Validations
  #

  validates :host,
            presence: true

  private

  # The `Mdm::Vuln` that has the most references in common compared to any other `Mdm::Vuln` in {#vulns}.
  #
  # @return [Mdm::Vuln]
  def closest_vuln
    expected_reference_ids = source.map(&:references).map(&:id)

    sorted_vulns = vulns.sort_by { |vuln|
      vuln_reference_ids = vuln.map(&:references).map(&:id)
      missing_reference_ids = expected_reference_ids - vuln_reference_ids

      missing_reference_ids.length
    }
    # prefer vuln with least missing references (tie picks arbitrary vuln with same number of missing references)
    sorted_vulns.first
  end

  def created_vuln
    vuln = Mdm::Vuln.create!(
        name: source.name,
        host: host,
        service: service
    )

    source.references.each do |reference|
      vuln.vuln_references.create!(
          reference: reference
      )
    end

    vuln
  end

  # @return [ActiveRecord::Relation<Mdm::Vuln>] vulns for {#source} and {#host}
  # @return [nil] if {#host} is a new record
  def host_vulns
    unless instance_variable_defined? :@host_vulns
      unless host.new_record?
        @host_vulns = vulns_scope.where(
            host_id: host.id
        )
      else
        @host_vulns = nil
      end
    end

    @host_vulns
  end

  def preexisting_vuln
    unless instance_variable_defined? :@preexisting_vuln
      unless vulns.blank?
        @preexisting_vuln = vuln_with_name
        @preexisting_vuln ||= closest_vuln
      else
        @preexisting_vuln = nil
      end
    end

    @preexisting_vuln
  end

  # @return [ActiveRecord::Relation<Mdm::Vuln>] vulns for {#source} and {#service}
  # @return [nil] if {#service} is nil or a new record
  def service_vulns
    unless instance_variable_defined? :@service_vulns
      if service && !service.new_record?
        @service_vulns = vulns_scope.where(
            service_id: service.id
        )
      else
        @service_vulns = nil
      end
    end

    @service_vulns
  end

  def vuln_with_name
    vulns.where(name: source.name).first
  end

  def vulns
    unless instance_variable_defined? :@vulns
      if service_vulns.blank?
        if host_vulns.blank?
          @vulns = nil
        else
          @vulns = host_vulns
        end
      else
        @vulns = service_vulns
      end
    end

    @vulns
  end

  # Scope for {#host_vulns} or {#service_vulns}.
  #
  # @return [ActiveRecord::Relation<Mdm::Vuln>]
  def vulns_scope
    source.vulns.includes(:references)
  end
end