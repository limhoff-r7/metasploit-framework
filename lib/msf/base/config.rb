# -*- coding: binary -*-
require 'fileutils'

module Msf

###
#
# This class wraps interaction with global configuration that can be used as a
# persistent storage point for configuration, logs, and other such fun things.
#
###
class Config < Hash
  #
  # Determines the base configuration directory.
  #
  def self.get_config_root
    Metasploit::Framework::Framework::Configuration.root.to_path
  end

  #
  # Default values
  #
  FileSep     = File::SEPARATOR
  Defaults    =
    {
      'ConfigDirectory'     => get_config_root
    }

  ##
  #
  # Class methods
  #
  ##

  #
  # Calls the instance method.
  #
  def self.config_directory
    self.new.config_directory
  end

  #
  # Calls the instance method.
  #
  def self.log_directory
    self.new.log_directory
  end

  #
  # Calls the instance method.
  #
  def self.user_plugin_directory
    self.new.user_plugin_directory
  end

  #
  # Calls the instance method.
  #
  def self.session_log_directory
    self.new.session_log_directory
  end

  #
  # Calls the instance method.
  #
  def self.loot_directory
    self.new.loot_directory
  end

  #
  # Calls the instance method.
  #
  def self.local_directory
    self.new.local_directory
  end

  #
  # Calls the instance method.
  #
  def self.user_module_directory
    self.new.user_module_directory
  end

  #
  # Calls the instance method.
  #
  def self.user_script_directory
    self.new.user_script_directory
  end

  #
  # Calls the instance method.
  #
  def self.config_file
    self.new.config_file
  end

  #
  # Calls the instance method.
  #
  def self.history_file
    self.new.history_file
  end

  #
  # Calls the instance method.
  #
  def self.init
    self.new.init
  end

  #
  # Calls the instance method.
  #
  def self.load(path = nil)
    self.new.load(path)
  end

  #
  # Calls the instance method.
  #
  def self.save(opts)
    self.new.save(opts)
  end

  #
  # Updates the config class' self with the default hash.
  #
  def initialize
    update(Defaults)
  end

  #
  # Returns the configuration directory default.
  #
  def config_directory
    self['ConfigDirectory']
  end

  #
  # Returns the full path to the configuration file.
  #
  def config_file
    config_directory + FileSep + 'config'
  end

  #
  # Returns the full path to the configuration file.
  #
  def history_file
    config_directory + FileSep + "history"
  end

  #
  # Returns the directory that log files should be stored in.
  #
  def log_directory
    config_directory + FileSep + 'logs'
  end

  #
  # Returns the directory in which session log files are to reside.
  #
  def session_log_directory
    config_directory + FileSep + 'logs/sessions'
  end

  #
  # Returns the directory in which captured data will reside.
  #
  def loot_directory
    config_directory + FileSep + 'loot'
  end

  #
  # Returns the directory in which locally-generated data will reside.
  #
  def local_directory
    config_directory + FileSep + 'local'
  end

  #
  # Returns the user-specific module base path
  #
  def user_module_directory
    config_directory + FileSep + "modules"
  end

  #
  # Returns the user-specific plugin base path
  #
  def user_plugin_directory
    config_directory + FileSep + "plugins"
  end

  #
  # Returns the user-specific script base path
  #
  def user_script_directory
    config_directory + FileSep + "scripts"
  end

  #
  # Initializes configuration, creating directories as necessary.
  #
  def init
    FileUtils.mkdir_p(config_directory)
    FileUtils.mkdir_p(log_directory)
    FileUtils.mkdir_p(session_log_directory)
    FileUtils.mkdir_p(loot_directory)
    FileUtils.mkdir_p(local_directory)
    FileUtils.mkdir_p(user_module_directory)
    FileUtils.mkdir_p(user_plugin_directory)
  end

  #
  # Loads configuration from the supplied file path, or the default one if
  # none is specified.
  #
  def load(path = nil)
    path = config_file if (!path)

    return Rex::Parser::Ini.new(path)
  end

  #
  # Saves configuration to the path specified in the ConfigFile hash key or
  # the default path is one isn't specified.  The options should be group
  # references that have named value pairs.  Example:
  #
  # save(
  #   'ExampleGroup' =>
  #      {
  #         'Foo' => 'Cat'
  #      })
  #
  def save(opts)
    ini = Rex::Parser::Ini.new(opts['ConfigFile'] || config_file)

    ini.update(opts)

    ini.to_file
  end

end

end

