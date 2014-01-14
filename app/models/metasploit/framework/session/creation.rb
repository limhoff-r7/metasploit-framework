class Metasploit::Framework::Session::Creation < Metasploit::Framework::Creation
  #
  # Attributes
  #

  # @!attribute [rw] source
  #   The in-memory session model that needs to be recorded in the database.
  #
  #   @return [Msf::Session]
  attr_accessor :source

  #
  # Creation
  #

  # @!method create
  #   Creates an `Mdm::Session`.
  #
  #   @raise [ActiveRecord::RecordInvalid] if `Mdm::Session` is invalid
  create do
    destination.architecture = architecture
    destination.datastore = source.exploit_datastore.to_h
    destination.desc = source.info
    destination.exploit_class = exploit_class
    destination.host = host
    destination.last_seen = now
    destination.local_id = source.sid
    destination.opened_at = now
    destination.payload_class = payload_class
    destination.platform = platform
    destination.port = source.session_port
    destination.stype = source.type
    destination.save!

    source.db_record = destination
  end

  #
  # Methods
  #

  def architecture
    unless instance_variable_defined? :@architecture
      abbreviation = source.architecture_abbreviation

      if abbreviation.present?
        @architecture = Mdm::Architecture.where(abbreviation: abbreviation).first
      else
        @architecture = nil
      end
    end

    @architecture
  end

  def destination
    @destination ||= Mdm::Session.new
  end

  def exploit_class
    unless instance_variable_defined? :@exploit_class
      if source.via_exploit == "exploit/multi/handler"
        full_name = source.exploit.datastore['ParentModule']
      end

      full_name ||= source.via_exploit

      @exploit_class = Mdm::Module::Class.where(full_name: full_name).first
    end

    @exploit_class ||= source.exploit.class.module_class
  end

  def host
    unless instance_variable_defined? :@host
      synchronization = Metasploit::Framework::Session::Synchronization::Host.new(source: source)
      synchronization.valid!
      synchronization.synchronize

      @host = synchronization.host
    end

    @host
  end

  def now
    @now ||= Time.now.utc
  end

  def payload_class
    unless instance_variable_defined? :@payload_class
      # break this chain of method calls up to make it clearer what each step does
      encoded_payload = source.exploit.payload
      payload_class = encoded_payload.payload_instance.class
      cache_payload_class = payload_class.module_class

      @payload_class = cache_payload_class
    end

    @payload_class
  end

  def platform
    unless instance_variable_defined? :@platform
      fully_qualified_name = source.platform_fully_qualified_name

      if fully_qualified_name.present?
        @platform = Mdm::Platform.where(fully_qualified_name: fully_qualified_name).first
      else
        @platform = nil
      end
    end

    @platform
  end
end
