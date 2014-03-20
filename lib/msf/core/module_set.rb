# -*- coding: binary -*-
require 'msf/core'
require 'pathname'

#
# Define used for a place-holder module that is used to indicate that the
# module has not yet been demand-loaded. Soon to go away.
#
Msf::SymbolicModule = '__SYMBOLIC__'

###
#
# A module set contains zero or more named module classes of an arbitrary
# type.
#
###
class Msf::ModuleSet < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] module_manager
  #   Collection of {Msf::ModuleSet module set}, one for each module type.
  #
  #   @return [Msf::ModuleManager]
  attr_accessor :module_manager

  # @!attribute [rw] module_type
  #   The `Metasploit::Model::Module::Class#module_type` for the metasploit Classes in this set.
  #
  #   @return [String] An element of `Metasploit::Model::Module::Type::ALL`.
  attr_accessor :module_type

  #
  # Validations
  #

  validates :module_manager,
            presence: true
  validates :module_type,
            inclusion: {
                in: Metasploit::Model::Module::Type::ALL
            }

  #
  # Methods
  #

  # @!method db
  #   Used to check whether the database is connected.
  #
  #   @return (see Msf::Framework#db)
  delegate :db,
           to: :framework

  # @!method cache
  #   The module cache that loads metasploit classes.
  #
  #   @return (see Msf::ModuleManager::Cache#cache)
  #
  # @!method framework
  #   Framework that should be notified of events and passed to {#create created instance}.
  #
  #   @return (see Msf::ModuleManager#framework)
  delegate :cache,
           :framework,
           to: :module_manager

  def count
    db.connection(
        with: ->{
          scope.count
        },
        without: ->{
          raise NotImplementedError
        }
    )
  end

  # Creates a metasploit instanc using the supplied `Mdm::Module::Class#reference_name`.
  # `Mdm::Module::Class#module_type` is assumed to be equal to {#module_type}.
  #
  # @param reference_name [String] An `Mdm::Module::Class#reference_name`.
  # @return (see Msf::ModuleManager#create)
  def create(reference_name)
    module_manager.create("#{module_type}/#{reference_name}")
  end

  # Enumerates each module class in the set.
  #
  # @param opts (see #each_module_list)
  # @yield (see #each_module_list)
  # @yieldparam (see #each_module_list)
  # @return (see #each_module_list)
  def each_module(opts = {}, &block)
    demand_load_modules

    self.mod_sorted = self.sort

    each_module_list(mod_sorted, opts, &block)
  end

  # Forces all modules in this set to be loaded.
  #
  # @return [void]
  def force_load_set
    each_module { |name, mod| }
  end

  # @param attributes [Hash{Symbol => String}]
  # @option attributes [String] :module_type An element from `Metasploit::Model::Module::Type::ALL`.
  def initialize(attributes={})
    super

    #
    # Defaults
    #
    self.ambiguous_module_reference_name_set = Set.new
    # Hashes that convey the supported architectures and platforms for a
    # given module
    self.architectures_by_module     = {}
    self.platforms_by_module = {}
    self.mod_sorted        = nil
    self.mod_ranked        = nil
    self.mod_extensions    = []
  end

  protected

  # Enumerates the modules in the supplied array with possible limiting factors.
  #
  # @param [Array<Array<String, Class>>] ary Array of module reference name and module class pairs
  # @param [Hash{String => Object}] opts
  # @option opts [Array<String>] 'Arch' List of 1 or more architectures that the module must support.  The module need
  #   only support one of the architectures in the array to be included, not all architectures.
  # @option opts [Array<String>] 'Platform' List of 1 or more platforms that the module must support.  The module need
  #   only support one of the platforms in the array to be include, not all platforms.
  # @yield [module_reference_name, module]
  # @yieldparam [String] module_reference_name the name of module
  # @yieldparam [Class] module The module class: a subclass of {Msf::Module}.
  # @return [void]
  def each_module_list(ary, opts, &block)
    ary.each { |entry|
      name, mod = entry

      # Skip any lingering symbolic modules.
      next if (mod == Msf::SymbolicModule)

      # Filter out incompatible architectures
      if (opts['Arch'])
        if (!architectures_by_module[mod])
          architectures_by_module[mod] = mod.new.arch
        end

        next if ((architectures_by_module[mod] & opts['Arch']).empty? == true)
      end

      # Filter out incompatible platforms
      if (opts['Platform'])
        if (!platforms_by_module[mod])
          platforms_by_module[mod] = mod.new.platform
        end

        next if ((platforms_by_module[mod] & opts['Platform']).empty? == true)
      end

      block.call(name, mod)
    }
  end

  # @!attribute [rw] ambiguous_module_reference_name_set
  #   Set of module reference names that are ambiguous because two or more paths have modules with the same reference
  #   name
  #
  #   @return [Set<String>] set of module reference names loaded from multiple paths.
  attr_accessor :ambiguous_module_reference_name_set
  # @!attribute [rw] architectures_by_module
  #   Maps a module to the list of architectures it supports.
  #
  #   @return [Hash{Class => Array<String>}] Maps module class to Array of architecture Strings.
  attr_accessor :architectures_by_module
  attr_accessor :mod_extensions
  # @!attribute [rw] platforms_by_module
  #   Maps a module to the list of platforms it supports.
  #
  #   @return [Hash{Class => Array<String>}] Maps module class to Array of platform Strings.
  attr_accessor :platforms_by_module
  # @!attribute [rw] mod_ranked
  #   Array of module names and module classes ordered by their Rank with the higher Ranks first.
  #
  #   @return (see #rank_modules)
  attr_accessor :mod_ranked
  # @!attribute [rw] mod_sorted
  #   Array of module names and module classes ordered by their names.
  #
  #   @return [Array<Array<String, Class>>] Array of arrays where the inner array is a pair of the module reference
  #     name and the module class.
  attr_accessor :mod_sorted

  # Ranks modules based on their constant rank value, if they have one.  Modules without a Rank are treated as if they
  # had {Msf::NormalRanking} for Rank.
  #
  # @return [Array<Array<String, Class>>] Array of arrays where the inner array is a pair of the module reference name
  #   and the module class.
  def rank_modules
    self.mod_ranked = self.sort { |a, b|
      a_name, a_mod = a
      b_name, b_mod = b

      # Dynamically loads the module if needed
      a_mod = create(a_name) if a_mod == Msf::SymbolicModule
      b_mod = create(b_name) if b_mod == Msf::SymbolicModule

      # Extract the ranking between the two modules
      a_rank = a_mod.const_defined?('Rank') ? a_mod.const_get('Rank') : Msf::NormalRanking
      b_rank = b_mod.const_defined?('Rank') ? b_mod.const_get('Rank') : Msf::NormalRanking

      # Compare their relevant rankings.  Since we want highest to lowest,
      # we compare b_rank to a_rank in terms of higher/lower precedence
      b_rank <=> a_rank
    }
  end

  private

  # Base scope for `Mdm::Module::Class` with `Mdm::Module::Class#module_type` equal to {#module_type}.
  #
  # @return [ActiveRecord::Relation]
  def scope
    db.with_connection do
      Mdm::Module::Class.where(module_type: module_type)
    end
  end
end
