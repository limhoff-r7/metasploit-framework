# -*- coding: binary -*-
require 'fileutils'

module Msf

# This class wraps interaction with global configuration that can be used as a
# persistent storage point for configuration, logs, and other such fun things.
class Config < Hash
  #
  # Determines the base configuration directory.
  #
  # @return [String] the base configuration directory
  def self.get_config_root
    Metasploit::Framework::Framework::Pathnames.root.to_path
  end

  #
  # Default values
  #

  # Default system file separator.
  FileSep     = File::SEPARATOR

  # Default configuration locations.
  Defaults    =
    {
      'ConfigDirectory'     => get_config_root
    }

  ##
  #
  # Class methods
  #
  ##

  # Returns the configuration directory default.
  #
  # @return [String] the root configuration directory.
  def self.config_directory
    self.new.config_directory
  end

  # Returns the global module directory.
  #
  # Calls the instance method.
  #
  def self.log_directory
    self.new.log_directory
  end

  # Returns the user-specific plugin base path
  #
  # @return [String] path to user-specific plugin directory.
  def self.user_plugin_directory
    self.new.user_plugin_directory
  end

  # Returns the directory in which session log files are to reside.
  #
  # @return [String] path to session log directory.
  def self.session_log_directory
    self.new.session_log_directory
  end

  # Returns the directory in which captured data will reside.
  #
  # @return [String] path to loot directory.
  def self.loot_directory
    self.new.loot_directory
  end

  # Returns the directory in which locally-generated data will reside.
  #
  # @return [String] path to locally-generated data directory.
  def self.local_directory
    self.new.local_directory
  end

  # Returns the user-specific module base path
  #
  # @return [String] path to user-specific modules directory.
  def self.user_module_directory
    self.new.user_module_directory
  end

  # Returns the user-specific script base path
  #
  # @return [String] path to user-specific script directory.
  def self.user_script_directory
    self.new.user_script_directory
  end

  # Returns the full path to the configuration file.
  #
  # @return [String] path to the configuration file.
  def self.config_file
    self.new.config_file
  end

  # Returns the full path to the history file.
  #
  # @return [String] path the history file.
  def self.history_file
    self.new.history_file
  end

  # Loads configuration from the supplied file path, or the default one if
  # none is specified.
  #
  # @param path [String] the path to the configuration file.
  # @return [Rex::Parser::Ini] INI file parser.
  def self.load(path = nil)
    self.new.load(path)
  end

  # Saves configuration to the path specified in the ConfigFile hash key or
  # the default path if one isn't specified.  The options should be group
  # references that have named value pairs.
  #
  # @param opts [Hash] Hash containing configuration options.
  # @option opts 'ConfigFile' [Hash] configuration file these options apply
  #   to.
  # @return [void]
  # @example Save 'Cat' => 'Foo' in group 'ExampleGroup'
  #   save(
  #     'ExampleGroup' =>
  #        {
  #           'Foo' => 'Cat'
  #        })
  def self.save(opts)
    self.new.save(opts)
  end

  # Updates the config class' self with the default hash.
  #
  # @return [Hash] the updated Hash.
  def initialize
    update(Defaults)
  end

  #
  # Returns the configuration directory default.
  #
  # @return [String] the root configuration directory.
  def config_directory
    self['ConfigDirectory']
  end

  # Returns the full path to the configuration file.
  #
  # @return [String] path to the configuration file.
  def config_file
    config_directory + FileSep + 'config'
  end

  # Returns the full path to the history file.
  #
  # @return [String] path the history file.
  def history_file
    config_directory + FileSep + "history"
  end

  #
  # Returns the directory that log files should be stored in.
  #
  # @return [String] path to log directory.
  def log_directory
    config_directory + FileSep + 'logs'
  end

  # Returns the directory in which session log files are to reside.
  #
  # @return [String] path to session log directory.
  def session_log_directory
    config_directory + FileSep + 'logs/sessions'
  end

  # Returns the directory in which captured data will reside.
  #
  # @return [String] path to loot directory.
  def loot_directory
    config_directory + FileSep + 'loot'
  end

  # Returns the directory in which locally-generated data will reside.
  #
  # @return [String] path to locally-generated data directory.
  def local_directory
    config_directory + FileSep + 'local'
  end

  # Returns the user-specific module base path
  #
  # @return [String] path to user-specific modules directory.
  def user_module_directory
    config_directory + FileSep + "modules"
  end

  # Returns the user-specific plugin base path
  #
  # @return [String] path to user-specific plugin directory.
  def user_plugin_directory
    config_directory + FileSep + "plugins"
  end

  # Returns the user-specific script base path
  #
  # @return [String] path to user-specific script directory.
  def user_script_directory
    config_directory + FileSep + "scripts"
  end

  # Loads configuration from the supplied file path, or the default one if
  # none is specified.
  #
  # @param path [String] the path to the configuration file.
  # @return [Rex::Parser::Ini] INI file parser.
  def load(path = nil)
    path = config_file if (!path)

    return Rex::Parser::Ini.new(path)
  end

  # Saves configuration to the path specified in the ConfigFile hash key or
  # the default path if one isn't specified.  The options should be group
  # references that have named value pairs.
  #
  # @param opts [Hash] Hash containing configuration options.
  # @option opts 'ConfigFile' [Hash] configuration file these options apply
  #   to.
  # @return [void]
  # @example Save 'Cat' => 'Foo' in group 'ExampleGroup'
  #   save(
  #     'ExampleGroup' =>
  #        {
  #           'Foo' => 'Cat'
  #        })
  def save(opts)
    ini = Rex::Parser::Ini.new(opts['ConfigFile'] || config_file)

    ini.update(opts)

    ini.to_file
  end

end

end

