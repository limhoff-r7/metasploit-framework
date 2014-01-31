class Metasploit::Framework::Module::Instance::Payload::Actual::Compatibility::Payload < Metasploit::Framework::Compatibility::Payload
  #
  # Attributes
  #

  # @!attribute [rw] architecture_abbreviations
  #   @return [Array<String>] `Mdm::Architecture#abbreviations`
  attr_accessor :architecture_abbreviations

  # @!attribute [rw] module_manager
  #   The {Msf::ModuleManager} that will be used to {Msf::ModuleManager#create}
  #   {Metasploit::Framework::Compatibility::Payload#each_compatible_instance}.
  #
  #   @return [Msf::ModuleManager]
  attr_accessor :module_manager

  # @!attribute [rw] platform_fully_qualified_names
  #   @return [Array<String>] `Mdm::Platform#fully_qualified_names`
  attr_accessor :platform_fully_qualified_names

  #
  # Validations
  #

  validates :architecture_abbreviations,
            presence: true
  validates :module_manager,
            presence: true
  validates :platform_fully_qualified_names,
            presence: true

  #
  # Methods
  #

  def each_compatible_cache_class(options={}, &block)
    options.assert_valid_keys(:include_generics)

    if options[:include_generics]
      raise ArgumentError,
            "Cannot :include_generics in #{self.class} as it will lead to an infinite recursion"
    end

    compatible_cache_instances = Mdm::Module::Instance.with_module_type(
        'payload'
    ).intersecting_architecture_abbreviations(
        architecture_abbreviations
    ).intersecting_platform_fully_qualified_names(
        platform_fully_qualified_names
    ).includes(
        :module_class
    )

    compatible_cache_classes = Mdm::Module::Class.non_generic_payloads.where(
        id: compatible_cache_instances.select(:module_class_id)
    )

    compatible_cache_classes.each(&block)
  end
end