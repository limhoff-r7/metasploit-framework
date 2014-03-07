require 'msf/core/framework'

# The {Msf::Framework#configuration configuration for a individual framework instance}.  Replaces the obsolete, global,
# `Msf::Config` to allow for individual {Msf::Framework} to have different configurations without interference.
class Metasploit::Framework::Framework::Pathnames < Metasploit::Model::Base
  #
  # CONSTANTS
  #

  FILE_BASE_NAME = 'config'
  # The base name of the {root} of the form .msf<major>.
  ROOT_BASE_NAME = ".msf#{Msf::Framework::Major}"
  # Name of environment variables that can hold the path to the directory that is the parent directory of {root}, in
  # order of precedence.
  ROOT_PARENT_ENVIRONMENT_VARIABLES = [
      'HOME',
      'LOCALAPPDATA',
      'APPDATA',
      'USERPROFILE'
  ]
  # Names of directory attributes that are children of {#root}
  SUBDIRECTORIES = %w{data local logs loot plugins modules scripts}
  # Names of all directory attributes
  DIRECTORIES = SUBDIRECTORIES + %w{root script_logs session_logs}

  #
  # Attributes
  #

  # @!attribute [r] database_yaml
  #   The path to the `database.yml` that includes connection information for this framework.
  #
  #   @return [Pathname]
  attr_reader :database_yaml

  # @!attribute [r] file
  #   The file under {#root} where framework settings like its data store and module data stores are persisted.
  #
  #   @return [Pathname]
  attr_reader :file

  # @!attribute [r] history
  #   The path to the command history for msfconsole.
  #
  #   @return [Pathname]
  attr_reader :history

  # @!attribute [r] data
  #   Directory where locally generated data is stored.
  #
  #   @return [Pathname]
  #
  # @!attribute [r] local
  #   Directory to store locally generated data.
  #
  #   @return [Pathname]
  #
  # @!attribute [r] logs
  #   Directory containing logs, including `framework.log` and individual session logs.
  #
  #   @return [Pathname]
  #
  # @!attribute [r] loot
  #   Directory where captured data will reside.
  #
  #   @return [Pathname]
  #
  # @!attribute [r] modules
  #   Module path for user-written modules.
  #
  #   @return [Pathname]
  #
  # @!attribute [r] plugins
  #   Directory where user-written plugins are stored.
  #
  #   @return [Pathname]
  #
  # @!attribute [rw] root
  #   The root directory under which the {#path} is located and the various configuration directories are
  #   created.
  #
  #   @return [Pathname]
  #
  # @!attribute [r] scripts
  #   Directory where user-written scripts are stored.
  #
  #   @return [Pathname]
  #
  # @!attribute [r] script_logs
  #   The directory for individual scripts logs.
  #
  #   @return [Pathname]
  #
  # @!attribute [r] session_logs
  #   The directory for individual {Msf::Session} logs.
  #
  #   @return [Pathname]
  attr_reader *DIRECTORIES

  #
  # Methods
  #

  # @param attributes [Hash{Symbol => Pathname,String}]
  # @option attributes [Pathname,String] :root The root path.  Defaults to {root} if not given.
  def initialize(attributes={})
    attributes.assert_valid_keys(:root)

    root = attributes[:root]

    if root
      root = Pathname.new(root)
    else
      root = self.class.root
    end

    # Expand path because mkpath doesn't understand ~ and so #make will attempt to create a directly actually named '~'.
    @root = root.expand_path

    SUBDIRECTORIES.each do |subdirectory|
      instance_variable_set "@#{subdirectory}", root.join(subdirectory)
    end

    database_yaml_path = ENV['MSF_DATABASE_CONFIG']

    if database_yaml_path
      @database_yaml = Pathname.new(database_yaml_path)
    else
      @database_yaml = @root.join('database.yml')
    end

    @file = root.join(FILE_BASE_NAME)
    @history = root.join('history')

    @script_logs = @logs.join('scripts')
    @session_logs = @logs.join('sessions')

    # Make immutable so that modules can safely access, but not write to paths.
    IceNine.deep_freeze(self)
  end

  # Makes all directories under {root}.
  #
  # @return [void]
  def make
    DIRECTORIES.each do |directory|
      send(directory).mkpath
    end
  end

  # Determines the root directory for configuration by checking environment variables, ~ expansion and finally, using
  # {Metasploit::Framework.root}.
  #
  # @return [Pathname]
  def self.root
    path = ENV['MSF_CFGROOT_CONFIG']
    root = nil

    if path && File.directory?(path)
      root = Pathname.new(path)
    else
      ROOT_PARENT_ENVIRONMENT_VARIABLES.each do |environment_variable|
        parent_path = ENV[environment_variable]

        if parent_path && File.directory?(parent_path)
          parent_pathname = Pathname.new(parent_path)
          root = parent_pathname.join(ROOT_BASE_NAME)

          break
        end
      end

      unless root
        begin
          parent_path = Dir.home
        rescue ArgumentError
          parent_pathname = Metasploit::Framework.root
        else
          parent_pathname = Pathname.new(parent_path).expand_path
        end

        root = parent_pathname.join(ROOT_BASE_NAME)
      end
    end

    root
  end
end