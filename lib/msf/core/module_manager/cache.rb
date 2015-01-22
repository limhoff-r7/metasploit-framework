module Msf::ModuleManager::Cache
  #
  # Return a listing of all cached modules
  #
  def cache_entries
    return {} if not (framework.db and framework.db.migrated)
    res = {}
    ::Mdm::ModuleDetail.find(:all).each do |m|
      res[m.file] = { :mtype => m.mtype, :refname => m.refname, :file => m.file, :mtime => m.mtime }
      unless module_set(m.mtype).has_key?(m.refname)
        module_set(m.mtype)[m.refname] = SymbolicModule
      end
    end

    res
  end

  #
  # Rebuild the cache for the module set
  #
  def rebuild_cache(mod = nil)
    return if not (framework.db and framework.db.migrated)
    if mod
      framework.db.update_module_details(mod)
    else
      framework.db.update_all_module_details
    end
    refresh_cache
  end

  #
  # Reset the module cache
  #
  def refresh_cache
    self.cache = cache_entries
  end

  attr_accessor :cache # :nodoc:
end