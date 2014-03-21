# Concerns the module cache maintained by the {Metasploit::Framework::Module::Instance::Creator::Universal}.
module Metasploit::Framework::Module::Instance::Creator::Universal::Cache
  # @return [Metasploit::Framework::Module::Cache]
  def cache
    unless instance_variable_defined? :@cache
      cache = Metasploit::Framework::Module::Cache.new(universal_module_instance_creator: self)
      cache.valid!

      @cache = cache
    end

    @cache
  end
end
