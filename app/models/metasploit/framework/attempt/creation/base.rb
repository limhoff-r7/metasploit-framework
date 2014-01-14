# Base class for creation one or more `Mdm::ExploitAttempt` and/or `Mdm::VulnAttempt`
class Metasploit::Framework::Attempt::Creation::Base < Metasploit::Framework::Creation
  #
  # Attributes
  #

  # @!attribute [rw] attempted_at
  #   When the attempt was made.
  #
  #   @return [DateTime]
  attr_writer :attempted_at

  # @!attribute [rw] cache_exploit_class
  #  `Mdm::Module::Class` referencing {#exploit_instance} or its parent module.
  #
  #  @param [Mdm::Module::Class]
  attr_writer :cache_exploit_class

  # @!attribute [rw] exploit_instance
  #   Instance of the {Msf::Exploit}.
  #
  #   @return [Msf::Exploit]
  attr_accessor :exploit_instance

  # @!attribute [rw] exploited
  #   Whether the attempt was successful or not.
  #
  #   @return [true] if attempt succeeded
  #   @return [false] if attempt failed
  attr_accessor :exploited

  #
  # Validations
  #

  validates :exploit_instance,
            presence: true
  validates :exploited,
            inclusion: {
                in: [
                    false,
                    true
                ]
            }

  #
  # Methods
  #

  # When the attempt was made.
  #
  # @return [DateTime] Default tos `Time.now.utc`.
  def attempted_at
    @attempted_at ||= Time.now.utc
  end

  def cache_exploit_class
    @cache_exploit_class ||= exploit_instance.class.module_class
  end

  def exploited?
    !!exploited
  end
end