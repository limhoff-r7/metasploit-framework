class Metasploit::Framework::Session::Synchronization::Host < Metasploit::Framework::Synchronization::Base
  #
  # Synchronization
  #

  synchronize do
    host.comm ||= ''
    host.scope = scope
    host.state = Msf::HostState::Alive
  end

  #
  # Validations
  #

  validates :address,
            ip_format: true,
            presence: true
  validates :workspace,
            presence: true

  #
  # Methods
  #

  def address
    unless instance_variable_defined? :@address
      @address = nil

      if address_with_scope
        @address, @scope = address_with_scope.split('%', 2)
      end
    end

    @address
  end

  def address_with_scope
    unless instance_variable_defined? :@address_with_scope
      address_with_scope = nil

      # Msf::Session
      if source.respond_to? :session_host
        address_with_scope = source.session_host
      end

      # Msf::Session object with an empty or nil tunnel_host and tunnel_peer;
      # see if it has a socket and use its peerhost if so.
      if address_with_scope.blank? && source.respond_to?(:sock)
        socket = source.sock

        if socket.respond_to? :peerhost
          peerhost = socket.peerhost

          if peerhost.to_s.length > 0
            address_with_scope = peerhost
          end
        end
      end

      @address_with_scope = address_with_scope
    end

    @address_with_scope
  end

  def architecture_abbreviation
    unless instance_variable_defined? :@architecture_abbreviation
      @architecture_abbreviation = nil

      if source.respond_to? :architecture_abbreviation
        architecture_abbreviation = source.architecture_abbreviation

        unless architecture_abbreviation.blank?
          @architecture_abbreviation = architecture_abbreviation
        end
      end
    end

    @architecture_abbreviation
  end

  def host
    @host ||= workspace.hosts.where(address: address_with_scope).first_or_initialize
  end

  def scope
    unless instance_variable_defined? :@scope
      @scope = nil

      if address_with_scope
        @address, @scope = address_with_scope.split('%', 2)
      end
    end

    @scope
  end

  def workspace
    @workspace ||= Mdm::Workspace.where(name: source.workspace).first
  end
end