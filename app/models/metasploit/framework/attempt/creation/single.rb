# Creation for one attempt: either an `Mdm::ExploitAttempt` or an `Mdm::VulnAttempt`.
class Metasploit::Framework::Attempt::Creation::Single < Metasploit::Framework::Attempt::Creation::Base
  #
  # CONSTANTS
  #

  # Valid values for {#attempt_type}.
  ATTEMPT_TYPES = [
      :exploit,
      :vuln
  ]

  #
  # Attributes
  #

  # @!attribute [rw] vuln
  #   The vulnerability tied to this attempt.
  #
  #   @return [Mdm::Vuln]
  attr_accessor :vuln

  #
  # Creation
  #

  create do
    cache_exploit_class.send("#{attempt_type}_attempts").create!(
        attributes
    )
  end

  #
  # Validations
  #

  validates :attempt_type,
            inclusion: {
                in: ATTEMPT_TYPES
            }
  validates :username,
            presence: true
  validates :vuln,
            presence: true

  #
  # Methods
  #

  # @!method fail_detail
  #   (see Msf::Exploit::Failure#fail_detail)
  #
  # @!method fail_reason
  #   (see Msf::Exploit::Failure#fail_reason)
  #
  delegate :fail_detail,
           :fail_reason,
           allow_nil: true,
           to: :exploit_instance

  # Name of user making the attempt.
  #
  # @return (see Msf::Module#owner)
  # @return [nil] if {#exploit_instance} is `nil`
  def username
    username = nil

    if exploit_instance
      username = exploit_instance.owner
    end

    username
  end

  protected

  def attempt_type
    self.class.attempt_type
  end

  # Attributes for the created attempt
  def attributes
    {
        attempted_at: attempted_at,
        exploited: exploited,
        fail_detail: fail_detail,
        fail_reason: fail_reason,
        module_class: cache_exploit_class,
        username: username,
        vuln: vuln
    }
  end
end