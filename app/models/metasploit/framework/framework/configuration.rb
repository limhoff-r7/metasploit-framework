require 'msf/core/framework'

# The {Msf::Framework#configuration configuration for a individual framework instance}.  Replaces the obsolete, global,
# `Msf::Config` to allow for individual {Msf::Framework} to have different configurations without interference.
class Metasploit::Framework::Framework::Configuration < Metasploit::Model::Base
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

  #
  # Attributes
  #

  # @!attribute [rw] file_pathname
  #   The path to the file where this configuration is persisted.
  #
  #   @return [Pathname]

  # @!attribute [rw] root
  #   The root directory under which the {#path} is located and the various configuration directories are
  #   created.
  #
  #   @return [Pathname]

  #
  # Methods
  #

  # The path to file where this configuration is persisted.
  #
  # @return [Pathname]
  def file_pathname
    @file_pathname ||= root.join(FILE_BASE_NAME)
  end

  # Sets path to file where this configuration is persisted.
  #
  # @param pathname [String, Pathname]
  # @return [Pathname]
  def file_pathname=(pathname)
    @file_pathname = Pathname.new(pathname)
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

  # The root directory under which the {#path} is located and the various configuration directories are
  # created.
  #
  # @return [Pathname]
  # @see root
  def root
    @root ||= self.class.root
  end

  # Sets root directory where the configuration {#path} is stored and the various configuration directories are
  # created.
  #
  # @param root [String, Pathname] the new configuration root
  # @return [Pathname]
  def root=(root)
    @root = Pathname.new(root)
  end
end