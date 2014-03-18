# -*- coding: binary -*-
require 'rex'
require 'msf/base'

# Interface for logging.
module Msf::Logging
  class Error < StandardError

  end

  class AlreadySetup < Error
    def initialize(options={})
      options.assert_valid_keys(:old, :new)

      super(
          "Cannot change to #{options.fetch(:new)} without calling Msf::Logging.teardown first: " \
          "Msf::Logging already setup with #{options.fetch(:old)} logs pathname"
      )
    end
  end

  class NotSetup < Error
    def initialize
      super("Msf::Logging.setup must be called before accessing Msf::Logging.logs_pathname")
    end
  end

  #
  # Class Variables
  #

  #Is session logging enabled
  #@private
  @session_logging = false

  #
  # Methods
  #

  # Stops logging for a given log source.
  #
  # @param src [String] the log source to disable.
  # @return [Boolean] true if successful. false if not.
  def self.disable_log_source(src)
    deregister_log_source(src)
  end

  # Enables a log source of name src. Creates the .log file in the
  # configured directory if logging is not already enabled for this
  # source.
  #
  # @param src [String] log source name.
  # @param level [Integer] logging level.
  # @return [void]
  def self.enable_log_source(src, level = 0)
    unless log_source_registered?(src)
      sink = Rex::Logging::Sinks::Flatfile.new(
          logs_pathname.join("#{src}.log")
      )

      register_log_source(src, sink, level)
    end
  end

  # Sets whether or not session logging is to be enabled.
  #
  # @param tf [Boolean] true if enabling. false if disabling.
  # @return [void]
  def self.enable_session_logging(tf)
    @session_logging = tf
  end

  # The directory under which log files are created.
  #
  # @return [Pathname] :logs_pathname passed to {setup}.
  # @raise [Msf::Logging::NotSetup] if {setup} has not been called to set {#logs_pathname}
  def self.logs_pathname
    unless @logs_pathname
      raise Msf::Logging::NotSetup
    end

    @logs_pathname
  end

  # Returns whether or not session logging is enabled.
  #
  # @return [Boolean] true if enabled. false if disabled.
  def self.session_logging_enabled?
    !!@session_logging
  end

  # Setups up logging for the given logs pathname.
  #
  # @param options [Hash{Symbol => Pathname}]
  # @option options [Pathname] :logs_pathname Pathname to directory where log files should be stored.
  # @return [void]
  # @raise [KeyError] unless :logs_pathname is given
  def self.setup(options={})
    options.assert_valid_keys(:logs_pathname)

    @logs_pathname = options.fetch(:logs_pathname)

    sink = Rex::Logging::Sinks::Flatfile.new(
        logs_pathname.join('framework.log')
    )

    sources.each do |source|
      register_log_source(source, sink)
    end
  end

  # Setups up logging for the given logs pathname, but raises an exception if logs are already setup.
  #
  # @param (see setup)
  # @option (see setup)
  # @return (see setup)
  # @raise (see setup)
  # @raise [Msf::Logging::AlreadySetup] if {teardown} wasn't called after the last call to {setup}.
  # @raise [Msf::Logging::SourceAlreadyRegistered] if a source is registered outside of setup.
  def self.setup!(options={})
    # have to access using instance variable so error checking on {logs_pathname} is not called.
    if @logs_pathname
      raise Msf::Logging::AlreadySetup.new(
                old: logs_pathname,
                new: options.fetch(:logs_pathname)
            )
    end

    setup(options)
  end

  # Sources for {setup}.
  #
  # @return [Array<String>]
  def self.sources
    @sources ||= [
        Rex::LogSource,
        Msf::LogSource,
        'base'
    ]
  end

  # Starts logging for a given session.
  #
  # @param session [Msf::Session] the session to start logging on.
  # @return [void]
  def self.start_session_log(session)
    unless log_source_registered?(session.log_source)
      sink = Rex::Logging::Sinks::Flatfile.new(
          logs_pathname.join('sessions', "#{session.log_file_name}.log")
      )

      register_log_source(session.log_source, sink)

      rlog("\n[*] Logging started: #{Time.now}\n\n", session.log_source)
    end
  end

  # Stops logging for a given session.
  #
  # @param session [Msf::Session] the session to stop logging.
  # @return [Boolean] true if sucessful. false if not.
  def self.stop_session_log(session)
    rlog("\n[*] Logging stopped: #{Time.now}\n\n", session.log_source)

    deregister_log_source(session.log_source)
  end

  # Deregisters log sources setup in {setup}.
  #
  # @return [void]
  def self.teardown
    # cannot use deregister_log_source because it tries to double-close sink file if multiple source have the same
    # sink, which the sources from {setup} do.
    $dispatcher.log_sinks_lock.synchronize do
      sources.each do |source|
        $dispatcher.log_sinks[source] = nil
      end
    end

    @logs_pathname = nil
  end
end
