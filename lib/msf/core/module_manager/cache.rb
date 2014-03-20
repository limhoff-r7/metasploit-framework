# Concerns the module cache maintained by the {Msf::ModuleManager}.
module Msf::ModuleManager::Cache
  # @return [Metasploit::Framework::Module::Cache]
  def cache
    unless instance_variable_defined? :@cache
      cache = Metasploit::Framework::Module::Cache.new(module_manager: self)
      cache.valid!

      @cache = cache
    end

    @cache
  end
end
