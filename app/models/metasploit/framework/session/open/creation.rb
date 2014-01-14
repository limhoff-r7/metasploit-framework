class Metasploit::Framework::Session::Open::Creation < Metasploit::Framework::Creation
  include Metasploit::Framework::Creation::Service

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

  create do
    create_attempts
    create_task_session
  end

  #
  # Methods
  #

  # Creates and `Mdm::Vuln` and its associated `Mdm::ExploitAttempt` and `Mdm::VulnAttempt`.
  #
  # @raise [ActiveRecord::RecordInvalid] if any record is invalid.
  def create_attempts
    creation = Metasploit::Framework::Attempt::Both::Creation.new(
        exploit_class: session.exploit_class,
        exploit_instance: exploit_instance,
        exploited: true,
        host: host,
        service: service
    )
    creation.valid!
    creation.create
  end

  # Creates an `Mdm::TaskSession` for {#session} if session has an exploit task.
  #
  # @raise [ActiveRecord::RecordInvalid] if `Mdm::TaskSession` is invalid.
  def create_task_session
    exploit_task = source.exploit_task

    if exploit_task
      task = exploit_task.record

      if task
        session.task_sessions.create(task: task)
      end
    end
  end

  def exploit_instance
    source.exploit
  end

  delegate :host,
           to: :session

  # Creates session in database mirroring the {#source in-memory Msf::Session}.
  #
  # @return [Mdm::Session]
  # @raise (see Metasploit::Framework::Session::Creation#create)
  def session
    unless @session
      creation = Metasploit::Framework::Session::Creation.new(
          source: source
      )
      creation.valid!
      creation.create

      @session = creation.destination
    end

    @session
  end
end