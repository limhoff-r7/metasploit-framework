# Derives the {#local} and {#remote} host for a {#metasploit_instance} when the user may not have set 'LHOST' and/or
# 'RHOST'.
class Metasploit::Framework::Module::Instance::Hosts < Metasploit::Model::Base
  #
  # CONSTANTS
  #

  # Invalid address passed to {Rex::Socket.source_address} when `metasploit_instance.data_store['RHOST']` is not set.
  DEFAULT_REMOTE = '50.50.50.50'

  #
  # Attributes
  #

  # @!attribute [rw] metasploit_instance
  #   The metasploit module instance whose {Msf::Module#data_store} supplies the 'LHOST' and/or 'RHOST'.
  #
  #   @return [Msf::Module]
  attr_accessor :metasploit_instance

  #
  # Validations
  #

  validates :metasploit_instance,
            presence: true

  #
  # Methods
  #

  # The default value for {#local} when `LHOST` is not set for {#metasploit_instance}.
  #
  # @return [String] an IPv4 address
  def default_local
    Rex::Socket.source_address(remote)
  end

  # The local host that the exploit should connect back to.  Uses `LHOST` if it is set for {#metasploit_instance}.
  # Fallbacks to {#default_local}.
  #
  # @return [String] an IP address
  def local
    unless instance_variable_defined? :@local
      local = metasploit_instance.data_store['LHOST']

      unless local
        local = default_local
      end

      @local = local
    end

    @local
  end


  # The remote host used to resolve {#default_local}.  Tries `RHOST` for {#metasploit_instance} first; otherwise,
  # fallback to {DEFAULT_REMOTE}.
  #
  # @return [String] an IP address
  def remote
    unless instance_variable_defined? :@remote
      remote = metasploit_instance.data_store['RHOST']

      unless remote
        remote = DEFAULT_REMOTE
      end

      @remote = remote
    end

    @remote
  end
end