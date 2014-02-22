# -*- coding: binary -*-

#
# Standard Library
#

require 'digest/md5'
require 'erb'
require 'fileutils'
require 'find'
require 'rexml/document'

#
# Project
#

require 'msf/base'
require 'msf/core'
require 'msf/ui'
require 'msf/ui/console/command_dispatcher'
require 'msf/ui/console/command_dispatcher/auxiliary'
require 'msf/ui/console/command_dispatcher/encoder'
require 'msf/ui/console/command_dispatcher/exploit'
require 'msf/ui/console/command_dispatcher/nop'
require 'msf/ui/console/command_dispatcher/payload'
require 'msf/ui/console/command_dispatcher/post'
require 'msf/ui/console/framework_event_manager'
require 'msf/ui/console/table'

# A user interface driver on a console interface.
class Msf::Ui::Console::Driver < Msf::Ui::Driver
  require 'msf/ui/console/driver/callback'
  include Msf::Ui::Console::Driver::Callback

  require 'msf/ui/console/driver/command_pass_through'
  include Msf::Ui::Console::Driver::CommandPassThrough

  require 'msf/ui/console/driver/configuration'
  include Msf::Ui::Console::Driver::Configuration

  require 'msf/ui/console/driver/fangs'
  include Msf::Ui::Console::Driver::Fangs

  require 'msf/ui/console/driver/history'
  include Msf::Ui::Console::Driver::History

  require 'msf/ui/console/driver/junit'
  include Msf::Ui::Console::Driver::JUnit

  require 'msf/ui/console/driver/prompt'
  include Msf::Ui::Console::Driver::Prompt

  require 'msf/ui/console/driver/resource'
  include Msf::Ui::Console::Driver::Resource

  # The console driver processes various framework notified events.
  include Msf::Ui::Console::FrameworkEventManager
  # The console driver is a command shell.
  include Rex::Ui::Text::DispatcherShell

  #
  # Attributes
  #

  # @!attribute [rw] active_session
  #   The active session associated with the driver.
  attr_accessor :active_session

  # @!attribute [rw] framework
  #   The framework instance associated with this driver.
  #
  #   @return [Msf::Simple::Framework]
  attr_accessor :framework

  # @!attribute [rw] metasploit_instance
  #   The active module associated with the driver.
  #
  #   @return [nil] if no metasploit module is active.
  #   @return [Msf::Module] if a metasploit module is active.
  attr_reader :metasploit_instance

  #
  # Methods
  #

  #
  # Initializes a console driver instance with the supplied prompt string and
  # prompt character.  The optional hash can take extra values that will
  # serve to initialize the console driver.
  #
  # The optional hash values can include:
  #
  # AllowCommandPassthru
  #
  # 	Whether or not unknown commands should be passed through and executed by
  # 	the local system.
  #
  # RealReadline
  #
  # 	Whether or to use the system Readline or the RBReadline (default)
  #
  # HistFile
  #
  #	Name of a file to store command history
  #
  def initialize(prompt = DEFAULT_PROMPT, prompt_char = DEFAULT_PROMPT_CHAR, opts = {})

    # Choose a readline library before calling the parent
    rl = false
    rl_err = nil
    begin
      if(opts['RealReadline'])
        require 'readline'
        rl = true
      end
    rescue ::LoadError
      rl_err = $!
    end

    # Default to the RbReadline wrapper
    require 'readline_compatible' if(not rl)

    histfile = opts['HistFile'] || Msf::Config.history_file

    # Initialize attributes
    self.framework = opts['Framework'] || Msf::Simple::Framework.create(opts)

    framework_data_store_prompt = self.framework.data_store['Prompt']

    if framework_data_store_prompt
      prompt = framework_data_store_prompt
      prompt_char = self.framework.data_store['PromptChar'] || DEFAULT_PROMPT_CHAR
    end

    # Call the parent
    super(prompt, prompt_char, histfile, framework)

    # Temporarily disable output
    self.disable_output = true

    # Load pre-configuration
    load_preconfig

    # Initialize the user interface to use a different input and output
    # handle if one is supplied
    input = opts['LocalInput']
    input ||= Rex::Ui::Text::Input::Stdio.new

    if (opts['LocalOutput'])
      if (opts['LocalOutput'].kind_of?(String))
        output = Rex::Ui::Text::Output::File.new(opts['LocalOutput'])
      else
        output = opts['LocalOutput']
      end
    else
      output = Rex::Ui::Text::Output::Stdio.new
    end

    init_ui(input, output)
    init_tab_complete

    # Add the core command dispatcher as the root of the dispatcher
    # stack
    enstack_dispatcher(Msf::Ui::Console::CommandDispatcher::Core)

    # Report readline error if there was one..
    if not rl_err.nil?
      print_error("***")
      print_error("* WARNING: Unable to load readline: #{rl_err}")
      print_error("* Falling back to RbReadLine")
      print_error("***")
    end


    # Add the database dispatcher if it is usable
    if (framework.db.valid?)
      require 'msf/ui/console/command_dispatcher/db'
      enstack_dispatcher(Msf::Ui::Console::CommandDispatcher::Db)
    else
      print_error("***")
      if framework.db.error == "disabled"
        print_error("* WARNING: Database support has been disabled")
      else
        print_error("* WARNING: No database support: #{framework.db.error.class} #{framework.db.error}")
      end
      print_error("***")
    end

    begin
      require 'openssl'
    rescue ::LoadError
      print_error("***")
      print_error("* WARNING: No OpenSSL support. This is required by meterpreter payloads and many exploits")
      print_error("* Please install the ruby-openssl package (apt-get install libopenssl-ruby on Debian/Ubuntu")
      print_error("***")
    end

    # Register event handlers
    register_event_handlers

    # Re-enable output
    self.disable_output = false

    # Whether or not command passthru should be allowed
    self.command_pass_through = (opts['AllowCommandPassthru'] == false) ? false : true

    # Disables "dangerous" functionality of the console
    @defanged = opts['Defanged'] == true

    # If we're defanged, then command passthru should be disabled
    if defanged?
      self.command_pass_through = false
    end

    # Parse any specified database.yml file
    if framework.db.valid? and not opts['SkipDatabaseInit']

      # Append any migration paths necessary to bring the database online
      if opts['DatabaseMigrationPaths']
        opts['DatabaseMigrationPaths'].each do |migrations_path|
          ActiveRecord::Migrator.migrations_paths << migrations_path
        end
      end

      # Look for our database configuration in the following places, in order:
      #	command line arguments
      #	environment variable
      #	configuration directory (usually ~/.msf3)
      database_yaml_path = opts['DatabaseYAML']
      database_yaml_pathname = nil

      if database_yaml_path
        database_yaml_pathname = Pathname.new(database_yaml_path)
      end

      database_connection = Metasploit::Framework::DatabaseConnection.new(
          database_yaml_pathname: database_yaml_pathname,
          db_manager: framework.db,
          environment: opts['DatabaseEnv']
      )

      unless database_connection.valid?
        lines = ['Database connection is invalid:']

        database_connection.errors.full_messages.each do |full_message|
          lines << "  #{full_message}"
        end

        unless framework.db.errors.empty?
          lines << ''
          lines << "  DBManager errors:"

          framework.db.errors.full_messages.each do |full_message|
            lines << "    #{full_message}"
          end
        end

        print_error(lines.join("\n"))
      end
    end

    # Initialize the module paths only if we didn't get passed a Framework instance
    unless opts['Framework']
      # Configure the framework module paths
      self.framework.add_module_paths

      module_path = opts['ModulePath']

      if module_path.present?
        # ensure that prefetching only occurs in 'ModuleCacheRebuild' thread
        self.framework.modules.add_path(module_path, prefetch: false)
      end

      # Rebuild the module cache in a background thread
      self.framework.threads.spawn("ModuleCacheRebuild", true) do
        self.framework.modules.cache.prefetch
      end
    end

    # Load console-specific configuration (after module paths are added)
    load_config(opts['Config'])

    # Process things before we actually display the prompt and get rocking
    on_startup(opts)

    # Process the resource script
    if opts['Resource'] and opts['Resource'].kind_of? Array
      opts['Resource'].each { |r|
        load_resource(r)
      }
    else
      # If the opt is nil here, we load ~/.msf3/msfconsole.rc
      load_resource(opts['Resource'])
    end

    # Process any additional startup commands
    if opts['XCommands'] and opts['XCommands'].kind_of? Array
      opts['XCommands'].each { |c|
        run_single(c)
      }
    end
  end

  # Sets the currently active metasploit instance.
  #
  # @param metasploit_instance [Msf::Module, nil]
  # @return [Msf::Module, nil] `metasploit_instance`
  def metasploit_instance=(metasploit_instance)
    if self.metasploit_instance
      # remove the metasploit_instance's dispatcher
      destack_dispatcher
    end

    @metasploit_instance = metasploit_instance

    if @metasploit_instance
      enstack_dispatcher(metasploit_instance_dispatcher_class)
      @metasploit_instance.init_ui(input, output)
    end

    restore_prompt

    @metasploit_instance
  end

  def metasploit_instance_dispatcher_class
    self.class.module_type_dispatcher_class(metasploit_instance.module_type)
  end

  # The dispatcher class used for the `use` shell for the given `module_type`.
  #
  # @return [Class]
  def self.module_type_dispatcher_class(module_type)
    "Msf::Ui::Console::CommandDispatcher::#{module_type.camelize}".constantize
  end

  def stop
    framework.events.on_ui_stop()
    super
  end

  protected

  # @!method flush
  #   Flushes the underlying {#output} `IO`.
  #
  #   @return [void]
  #
  # @!method tty?
  #   Whether the underlying {#output} `IO` is a TTY.
  #
  #   @return [true] if it is a TTY.
  #   @return [false] if not a TTY or a mix of a TTY and other IO.
  #
  # @!method width
  #   Width of the output TTY.
  #
  #   @return [80] if output is not a TTY.
  #   @return [Integer] if output is a TTY.
  delegate :flush,
           :tty?,
           :width,
           to: :output
end
