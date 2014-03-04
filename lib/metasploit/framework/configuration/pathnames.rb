# Pathnames relative to `Metasploit::Framework.root`
class Metasploit::Framework::Configuration::Pathnames < Metasploit::Model::Base
  #
  # CONSTANTS
  #

  SUBDIRECTORIES = %w{data modules plugins scripts}

  # @!attribute [rw] root
  #   Root directory for metasploit-framework install.
  #
  #   @return [Pathname]
  attr_accessor :root

  #
  # Methods
  #

  # @!method data
  #   Data used by modules.
  #
  #   @return [Pathname]
  #
  # @!method modules
  #   Default module path for modules that ship with metasploit-framework.
  #
  #   @return [Pathname]
  #
  # @!method plugins
  #   Plugins for msfconsole.
  #
  #   @return [Pathname]
  #
  # @!method scripts
  #   Scripts
  #
  #   @return [Pathname]
  SUBDIRECTORIES.each do |subdirectory|
    instance_variable_name = "@#{subdirectory}"

    define_method(subdirectory) do
      unless instance_variable_defined? instance_variable_name
        instance_variable_set instance_variable_name, root.join(subdirectory)
      end

      instance_variable_get instance_variable_name
    end
  end

  # Various files used for exploits
  #
  # @return [Pathname]
  def exploit_data
    @exploit_data ||= data.join('exploits')
  end

  # Java .class files
  #
  # @return [Pathname]
  def java_classes
    @java_classes ||= data.join('java')
  end

  # Wordlists data.
  #
  # @return [Pathname]
  def wordlists
    @wordlists ||= data.join('wordlists')
  end
end