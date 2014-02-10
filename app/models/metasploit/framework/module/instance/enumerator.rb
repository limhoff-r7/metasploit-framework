# Allow to enumerator {Msf::Module module instances} created from an `ActiveRecord::Relation<Mdm::Module::Class>`.
class Metasploit::Framework::Module::Instance::Enumerator < Metasploit::Model::Base
  include Enumerable
  include Metasploit::Framework::Module::Class::Logging

  #
  # Attributes
  #

  # @!attribute [rw] cache_module_classes
  #   The module classes in the cache
  #
  #   @return [ActiveRecord::Relation<Mdm::Module::Class>]
  attr_accessor :cache_module_classes

  # @!attribute [rw] module_manager
  #   The module manager that can create {Msf::Module module instances} from `Mdm::Module::Class`.
  #
  #   @return [Msf::ModuleManager]
  attr_accessor :module_manager

  #
  # Validations
  #

  validates :cache_module_classes,
            presence: true
  validates :module_manager,
            presence: true

  # Yields each successively created {Msf::Module} from {#cache_module_classes}.  If an {Msf::Module} cannot be created
  # from a given `Mdm::Module::Class`, then the {#module_class_location} is logged as an error.
  #
  # @yield [module_instance]
  # @yieldparam module_instance [Msf::Module] Module created by {Msf::ModuleManager#create_from_module_class}
  # @yieldreturn [void]
  # @return [void]
  def each
    unless block_given?
      to_enum(__method__)
    else
      cache_module_classes.each do |cache_module_class|
        module_instance = module_manager.create_from_module_class(cache_module_class)

        if module_instance
          yield module_instance
        else
          module_class_location = self.module_class_location(cache_module_class)
          elog("Skipping #{module_class_location}: failed to create instance")
        end
      end
    end
  end
end