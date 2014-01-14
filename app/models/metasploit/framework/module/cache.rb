class Metasploit::Framework::Module::Cache < Metasploit::Model::Base
  include Metasploit::Framework::Module::Class::Logging

  #
  # CONSTANTS
  #

  # Can be actual class references and not Class#names since there is no problem with circular loading.
  MODULE_CLASS_LOAD_CLASS_BY_PAYLOAD_TYPE_BY_MODULE_TYPE = {
      Metasploit::Model::Module::Type::AUX => {
          nil => Metasploit::Framework::Module::Class::Load::NonPayload
      },
      Metasploit::Model::Module::Type::ENCODER => {
          nil => Metasploit::Framework::Module::Class::Load::NonPayload
      },
      Metasploit::Model::Module::Type::EXPLOIT => {
          nil => Metasploit::Framework::Module::Class::Load::NonPayload
      },
      Metasploit::Model::Module::Type::NOP => {
          nil => Metasploit::Framework::Module::Class::Load::NonPayload
      },
      Metasploit::Model::Module::Type::PAYLOAD => {
          'single' => Metasploit::Framework::Module::Class::Load::Payload::Single,
          'staged' => Metasploit::Framework::Module::Class::Load::Payload::Staged
      },
      Metasploit::Model::Module::Type::POST => {
          nil => Metasploit::Framework::Module::Class::Load::NonPayload
      }
  }

  #
  # Attributes
  #

  # @!attribute [rw] module_manager
  #   The module manager using this cache.
  #
  #   @return [Msf::ModuleManager]
  attr_accessor :module_manager

  #
  # Validations
  #

  validates :module_manager,
            :presence => true

  #
  # Methods
  #

  # @!method framework
  #   Framework to pass to metasploit instances in {#write_module_ancestor_load}.
  #
  #   @return [Msf::Simple::Framework]
  delegate :framework,
           to: :module_manager

  # Either finds in-memory or loads into memory ruby `Class` described by `module_class`.
  #
  # @param module_class [Metasploit::Model::Module::Class] metadata about ruby `Class` to return
  # @return [Class]
  # @return [nil] if Class could not be loaded into memory.
  def metasploit_class(module_class)
    metasploit_class = nil

    module_class_load_class_by_payload_type = MODULE_CLASS_LOAD_CLASS_BY_PAYLOAD_TYPE_BY_MODULE_TYPE[module_class.module_type]

    if module_class_load_class_by_payload_type
      module_class_load_class = module_class_load_class_by_payload_type[module_class.payload_type]

      if module_class_load_class
        module_class_load = module_class_load_class.new(cache: self, module_class: module_class)

        if module_class_load.valid?
          metasploit_class = module_class_load.metasploit_class
        end
      end
    end

    metasploit_class
  end

  # Set of paths this cache using to load `Metasploit::Model::Ancestors`.
  #
  # @return [Metasploit::Framework::Module::PathSet::Base]
  def path_set
    unless instance_variable_defined? :@path_set
      path_set = Metasploit::Framework::Module::PathSet::Database.new(
          cache: self
      )
      path_set.valid!

      @path_set = path_set
    end

    @path_set
  end

  def default_progress_bar_factory
    Metasploit::Framework::NullProgressBar.new
  end

  # Checks that this cache is up-to-date by scanning the
  # `Metasploit::Model::Path#real_path` of each `Metasploit::Module::Path` in
  # {#path_set} for updates to `Metasploit::Model::Module::Ancestors`.
  #
  # @param options [Hash]
  # @option options [Boolean] :changed (false) if `true`, assume the
  #   {Mdm::Module::Ancestor#real_path_modified_at} and
  #   {Mdm::Module::Ancestor#real_path_sha1_hex_digest} have changed and that
  #   {Mdm::Module::Ancestor} should be returned.
  # @option options [nil, Metasploit::Model::Module::Path, Array<Metasploit::Model::Module::Path>] :only only prefetch
  #   the given module paths.  If :only is not given, then all module paths in
  #   {#path_set} will be prefetched.
  # @option options [#call] :progress_bar_factory A factory that produces a ruby `ProgressBar` or similar object that
  #   supports the `#total=` and `#increment` API for monitoring the progress of the enumerator.  `#total` will be set
  #   to total number of {#module_ancestor_real_paths real paths} under this module path, not just the number of changed
  #   (updated or new) real paths.  `#increment` will be called whenever a real path is visited, which means it can be
  #   called when there is no yielded module ancestor because that module ancestor was unchanged.  When
  #   {#each_changed_module_ancestor} returns, `#increment` will have been called the same number of times as the value
  #   passed to `#total=` and `#finished?` will be `true`.
  # @return [void]
  # @raise (see Metasploit::Framework::Module::PathSet::Base#superset!)
  def prefetch(options={})
    options.assert_valid_keys(:changed, :only, :progress_bar_factory)

    changed = options.fetch(:changed, false)
    progress_bar_factory = options[:progress_bar_factory] || method(:default_progress_bar_factory)
    module_paths = Array.wrap(options[:only])

    if module_paths.blank?
      module_paths = path_set.all
    else
      path_set.superset!(module_paths)
    end

    # TODO generalize to work with or without ActiveRecord for in-memory models
    ActiveRecord::Base.connection_pool.with_connection do
      module_paths.each do |module_path|
        progress_bar = progress_bar_factory.call
        module_path_load = Metasploit::Framework::Module::Path::Load.new(
            cache: self,
            changed: changed,
            module_path: module_path,
            progress_bar: progress_bar
        )

        module_path_load.each_module_ancestor_load do |module_ancestor_load|
          write_module_ancestor_load(module_ancestor_load)
        end

        dlog("#{module_path.real_path} prefetched")
      end
    end

    dlog("#{module_paths.map(&:real_path).to_sentence} prefetched")
  end

  # Writes `Metasploit::Model::Module::Class` and `Metasploit::Model::Module::Instance` derived from
  # `module_ancestor_load` to this cache.  Only updates cache if `module_ancestor_load` is valid.
  #
  # @param module_ancestor_load [Metasploit::Framework::Module::Ancestor::Load] load of a
  #   `Metasploit::Model::Module::Ancestor`.
  # @return [true] if cache was written because `module_ancestor_load` was valid.
  # @return [false] if cache was not written because `module_ancestor_load` was not valid.
  def write_module_ancestor_load(module_ancestor_load)
    written = true

    # TODO log validation errors
    # validate under batch mode to prevent uniqueness validations on module_ancestor
    valid = MetasploitDataModels::Batch.batch {
      module_ancestor_load.valid?
    }

    if valid
      metasploit_module = module_ancestor_load.metasploit_module

      begin
        metasploit_module.each_metasploit_class do |metasploit_class|
          module_class = metasploit_class.cache_module_class

          if module_class.persisted?
            begin
              metasploit_instance = metasploit_class.new(framework: framework)
            rescue Exception => exception
              # need to rescue Exception because the user could screw up #initialize in unknown ways for each combined
              # metasploit_class
              elog("#{exception.class} #{exception}:\n#{exception.backtrace.join("\n")}")
              written &= false
            else
              if metasploit_instance.valid?
                metasploit_instance.cache_module_instance
                written &= true
              else
                location = module_class_location(module_class)
                elog("Msf::Module instance of #{location} is invalid: #{metasploit_instance.errors.full_messages}")
                written &= false
              end
            end
          else
            written &= false
          end
        end
      rescue Exception => exception
        # need to rescue Exception because the use could screw up #initialize for the
        # {Metasploit::Framework::Module::Ancestor::MetasploitModule#payload_metasploit_class}, which can be used by
        # {Metasploit::Framework::Module::Ancestor::MetasploitModule#each_metasploit_class}
        elog("#{exception.class} #{exception}:\n#{exception.backtrace.join("\n")}")
        written = false
      end
    else
      written = false
    end

    written
  end
end