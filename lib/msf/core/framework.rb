# -*- coding: binary -*-

#
# Standard Library
#

require 'monitor.rb'

#
# Project
#

require 'msf/core'
require 'msf/core/session_event'
require 'msf/util'

module Msf

###
#
# This class is the primary context that modules, scripts, and user
# interfaces interact with.  It ties everything together.
#
###
class Framework < Metasploit::Model::Base
  # Use MonitorMixin instead of Mutex_m to get #synchronize as Monitors are reentrant while mutexes aren't, so
  # #synchronize can be called instead an outer #synchronize block when using a monitor.
  # Use a monitor allows for lazy initialization of children, which makes testing those children easier.
  include MonitorMixin

  require 'msf/core/framework/modules'
  include Msf::Framework::Modules

  #
  #
  # CONSTANTS
  #
  #

  #
  # Versioning information
  #

  Major    = 4
  Minor    = 8
  Point    = 0
  Release  = "-dev"

  if(Point)
    Version  = "#{Major}.#{Minor}.#{Point}#{Release}"
  else
    Version  = "#{Major}.#{Minor}#{Release}"
  end

  Revision = "$Revision$"

  # Repository information
  RepoRevision        = ::Msf::Util::SVN.revision
  RepoUpdated         = ::Msf::Util::SVN.updated
  RepoUpdatedDays     = ::Msf::Util::SVN.days_since_update
  RepoUpdatedDaysNote = ::Msf::Util::SVN.last_updated_friendly
  RepoUpdatedDate     = ::Msf::Util::SVN.last_updated_date
  RepoRoot            = ::Msf::Util::SVN.root

  # EICAR canary
  EICARCorrupted      = ::Msf::Util::EXE.is_eicar_corrupted?

  # API Version
  APIMajor = 1
  APIMinor = 0

  # Base/API Version
  VersionCore  = Major + (Minor / 10.0)
  VersionAPI   = APIMajor + (APIMinor / 10.0)

  #
  # Mixin meant to be included into all classes that can have instances that
  # should be tied to the framework, such as modules.
  #
  module Offspring

    #
    # A reference to the framework instance from which this offspring was
    # derived.
    #
    attr_accessor :framework
  end

  #
  # Attributes
  #
  
  # @!attribute [r] pathnames
  #   @note Pathnames is immutable and unchanging after {#initialize} returns, so it is safe to return a local copy
  #     in other threads and not worry about mutation.
  #
  #   Framework-specific pathnames for {Metasploit::Framework::Framework::Pathnames#file configuration file},
  #   {Metasploit::Framework::Framework::Pathnames#history msfconsole history}, etc.
  #
  #   @return [Metasploit::Framework::Framework::Pathnames]
  attr_reader :pathnames

  # @!attribute [rw] database_disabled
  #   Whether {#db} should be {Msf::DBManager#disabled}.
  #
  #   @return [Boolean] Defaults to `false`.

  #
  # Methods
  #

  def database_disabled
    @database_disabled ||= false
  end
  alias database_disabled? database_disabled
  attr_writer :database_disabled

  # Requires need to be here because they use Msf::Framework::Offspring, which is declared immediately before this.
  require 'msf/core/db_manager'
  require 'msf/core/event_dispatcher'
  require 'msf/core/plugin_manager'
  require 'msf/core/session_manager'

  # @!method datastore
  #   (see #data_store)
  #   @deprecated Use {#data_store}
  Metasploit::Framework::Deprecation.rename_methods self, datastore: :data_store

  # The global framework data store that can be used by modules.
  #
  # @return [Msf::DataStore]
  def data_store
    synchronize {
      @data_store ||= Msf::DataStore.new
    }
  end

  # Maintains the database and handles database events
  #
  # @return [Msf::DBManager]
  def db
    synchronize {
      @db ||= Msf::DBManager.new(framework: self)
    }
  end

  # Event management interface for registering event handler subscribers and
  # for interacting with the correlation engine.
  #
  # @return [Msf::EventDispatcher]
  def events
    synchronize {
      unless instance_variable_defined? :@events
        events = Msf::EventDispatcher.new(self)

        subscriber = Msf::FrameworkEventSubscriber.new(self)
        events.add_exploit_subscriber(subscriber)
        events.add_session_subscriber(subscriber)
        events.add_general_subscriber(subscriber)
        events.add_db_subscriber(subscriber)
        events.add_ui_subscriber(subscriber)

        @events = events
      end

      @events
    }
  end

  # @param attributes [Hash{Symbol => Object}]
  # @option attributes [Boolean] :database_disabled (false) Whether the {#db} should disable connections.
  # @option attributes [Array<String>] :module_types a subset of `Metasploit::Model::Module::Type::ALL`.
  # @option attributes [Metasploit::Framework::Framework::Pathnames] :pathnames
  #   (Metasploit::Framework::Framework::Pathnames.new) pathnames for this framework instances.
  def initialize(attributes={})
    attributes.assert_valid_keys(:database_disabled, :module_types, :pathnames)

    @pathnames = attributes[:pathnames] || Metasploit::Framework::Framework::Pathnames.new

    super_attributes = attributes.except(:pathnames)
    # call super to initialize MonitorMixin and set attributes with Metasploit::Model::Base
    super(super_attributes)

    # Configure the thread factory
    # @todo https://www.pivotaltracker.com/story/show/57432206
    Rex::ThreadFactory.provider = self.threads
  end

  # Background job management specific to things spawned from this instance
  # of the framework.
  #
  # @return [Rex::JobContainer]
  def jobs
    synchronize {
      # @todo https://www.pivotaltracker.com/story/show/57432316
      @jobs ||= Rex::JobContainer.new
    }
  end

  # The plugin manager allows for the loading and unloading of plugins.
  #
  # @return [Msf::PluginManager]
  def plugins
    synchronize {
      @plugins ||= Msf::PluginManager.new(self)
    }
  end

  # Session manager that tracks sessions associated with this framework
  # instance over the course of their lifetime.
  #
  # @return []
  def sessions
    synchronize {
      @sessions ||= Msf::SessionManager.new(self)
    }
  end

  # The thread manager provides a cleaner way to manage spawned threads.
  #
  # @return [Metasploit::Framework::Thread::Manager]
  def threads
    synchronize {
      @threads ||= Metasploit::Framework::Thread::Manager.new(framework: self)
    }
  end

  #
  # Returns the framework version in Major.Minor format.
  #
  def version
    Version
  end
end
end

require 'msf/core/framework_event_subscriber'
