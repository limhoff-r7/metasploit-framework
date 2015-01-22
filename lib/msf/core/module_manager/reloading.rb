module Msf::ModuleManager::Reloading
  #
  # Reloads the module specified in mod.  This can either be an instance of a
  # module or a module class.
  #
  def reload_module(mod)
    omod    = mod
    refname = mod.refname
    ds      = mod.datastore

    dlog("Reloading module #{refname}...", 'core')

    # Set the target file
    file = mod.file_path
    wrap = ::Module.new

    # Load the module into a new Module wrapper
    begin
      wrap.module_eval(load_module_source(file), file)
      if(wrap.const_defined?(:RequiredVersions))
        mins = wrap.const_get(:RequiredVersions)
        if( mins[0] > ::Msf::Framework::VersionCore or
            mins[1] > ::Msf::Framework::VersionAPI
        )
          errmsg = "Failed to load module from #{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
          elog(errmsg)
          self.module_failed[mod.file_path] = errmsg
          return false
        end
      end
    rescue ::Exception => e

      # Hide eval errors when the module version is not compatible
      if(wrap.const_defined?(:RequiredVersions))
        mins = wrap.const_get(:RequiredVersions)
        if( mins[0] > ::Msf::Framework::VersionCore or
            mins[1] > ::Msf::Framework::VersionAPI
        )
          errmsg = "Failed to reload module from #{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
          elog(errmsg)
          self.module_failed[mod.file_path] = errmsg
          return
        end
      end

      errmsg = "Failed to reload module from #{file}: #{e.class} #{e}"
      elog(errmsg)
      self.module_failed[mod.file_path] = errmsg
      return
    end

    added = nil
    ::Msf::Framework::Major.downto(1) do |major|
      if wrap.const_defined?("Metasploit#{major}")
        added = wrap.const_get("Metasploit#{major}")
        break
      end
    end

    if not added
      errmsg = "Reloaded file did not contain a valid module (#{file})."
      elog(errmsg)
      self.module_failed[mod.file_path] = errmsg
      return nil
    end

    self.module_failed.delete(mod.file_path)

    # Remove the original reference to this module
    self.delete(mod.refname)

    # Indicate that the module is being loaded again so that any necessary
    # steps can be taken to extend it properly.
    on_module_load(added, mod.type, refname, {
                            'files' => [ mod.file_path ],
                            'noup'  => true})

    # Create a new instance of the module
    if (mod = create(refname))
      mod.datastore.update(ds)
    else
      elog("Failed to create instance of #{refname} after reload.", 'core')
      # Return the old module instance to avoid a strace trace
      return omod
    end

    # Let the specific module sets have an opportunity to handle the fact
    # that this module was reloaded.
    module_sets[mod.type].on_module_reload(mod)

    # Rebuild the cache for just this module
    rebuild_cache(mod)

    mod
  end

  #
  # Reloads modules from all module paths
  #
  def reload_modules

    self.module_history = {}
    self.clear

    self.enabled_types.each_key do |type|
      module_sets[type].clear
      init_module_set(type)
    end

    # The number of loaded modules in the following categories:
    # auxiliary/encoder/exploit/nop/payload/post
    count = 0
    module_paths.each do |path|
      mods = load_modules(path, true)
      mods.each_value {|c| count += c}
    end

    rebuild_cache

    count
  end
end