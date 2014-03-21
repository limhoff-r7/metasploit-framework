# Deals with module paths in the {Metasploit::Framework::Module::Instance::Creator::Universal}
module Metasploit::Framework::Module::Instance::Creator::Universal::ModulePaths
  # Adds a path to {#cache} and then searches the path for modules.
  #
  # @param path [String] a `Metasploit::Model::Module::Path#real_path`.
  # @param options [Hash{Symbol => Object}]
  # @option (see Metasploit::Framework::Pathset::Base#add)
  # @option options [Boolean] :prefetch (true) {Metasploit::Framework::Module::Cache#prefetch Prefetch} the
  #   {Metasploit::Framework::Module::Path} added to the {Metasploit::Framework::Module::Cache#path_set}.  If `false`,
  #   then caller is responsible for prefetching the
  # @return [void]
  def add_path(path, options={})
    options.assert_valid_keys(:gem, :name, :prefetch)

    module_path = cache.path_set.add(path, gem: options[:gem], name: options[:name])

    prefetch = options.fetch(:prefetch, true)

    if prefetch
      cache.prefetch(only: module_path)
    end
  end
end