# Concerns reloading modules
module Msf::ModuleManager::Reloading
  # Reloads the module specified in mod.  This can either be an instance of a module or a module class.
  #
  # @param [Msf::Module, Class] mod either an instance of a module or a module class
  # @return (see Metasploit::Framework::Module::Path::Load#reload_module)
  def reload_module(mod)
    # if it's can instance, then get its class
    if mod.is_a? Msf::Module
      metasploit_class = mod.class
    else
      metasploit_class = mod
    end

    namespace_module = metasploit_class.parent
    loader = namespace_module.loader
    loader.reload_module(mod)
  end
end
