# -*- coding: binary -*-

# Instantiates {Msf::Module module classes} and associates them with {#framework}.  {Msf::Module} instances can be
# created from a {Mdm::Module::Class#reference_name} using {#create} or from a {Mdm::Module::Class} using
# {#create_from_module_class}.
class Metasploit::Framework::Module::Instance::Creator::Universal < Metasploit::Model::Base
  include Metasploit::Framework::Module::Instance::Creator::Universal::Cache
  include Metasploit::Framework::Module::Instance::Creator::Universal::ModulePaths
  include Metasploit::Framework::Module::Instance::Creator::Universal::ModuleSets

  #
  # Attributes
  #

  # @!attribute [rw] framework
  #   Framework for which this module manager is managing modules.
  #
  #   @return [Msf::Simple::Framework]
  attr_accessor :framework

  #
  # Validations
  #

  validates :framework,
            presence: true

  #
  # Methods
  #

  # @note If you already have an `Mdm::Module::Class`, use {#create_from_module_class} as it will eliminate the need
  #   to query the database for an `Mdm::Module::Class` using `Mdm::Module::Class#full_name`.
  #
  # Creates a metasploit instance using the supplied `Mdm::Module::Class#full_name`.
  #
  # @param full_name [String] An `Mdm::Module::Class#full_name`.
  # @return [Msf::Module] Instance of the named module.
  # @return [nil] if there is no `Mdm::Module::Class` with the given name OR the metasploit class referenced by
  #   `Mdm::Module::Class` cannot be loaded (i.e. because its ancestor files don't exist on disk or have an error)
  # @see #create_from_module_class
  def create(full_name)
    metasploit_instance = nil
    module_class = Mdm::Module::Class.where(full_name: full_name).first

    if module_class
      metasploit_instance = create_from_module_class(module_class)
    end

    metasploit_instance
  end

  # @note If you don't have an `Mdm::Module::Class`, but only an `Mdm::Module::Class#full_name`, then use {#create}, as
  #   it will look up the `Mdm::Module::Class` for you and handle the `Mdm::Module::Class` not existing.
  #
  # Creates a metasploit instance using the supplied `Mdm::Module::Class`.
  #
  # @param module_class [Mdm::Module::Class] metadata describing a module class to load or grab from memory
  #   (if already loaded).
  # @return [Msf::Module] Instance of the named module class.
  # @return [nil] if the metasploit class referenced by `module_class` cannot be loaded (i.e. because its ancestor files
  #   don't exist on disk or have an error)
  # @see #create
  def create_from_module_class(module_class)
    metasploit_instance = nil
    metasploit_class = cache.metasploit_class(module_class)

    if metasploit_class
      metasploit_instance = metasploit_class.new(framework: framework)
      framework.events.on_module_created(metasploit_instance)
    end

    metasploit_instance
  end
end
