module Msf::Ui::Console::CommandDispatcher::Db::DbRebuildCache
  def cmd_db_rebuild_cache
    unless framework.db.active
      print_error("The database is not connected")
      return
    end

    print_status("Purging and rebuilding the module cache in the background...")
    framework.threads.spawn("ModuleCacheRebuild", true) do
      framework.db.purge_all_module_details
      framework.db.update_all_module_details
    end
  end

  def cmd_db_rebuild_cache_help
    print_line "Usage: db_rebuild_cache"
    print_line
    print_line "Purge and rebuild the SQL module cache."
    print_line
  end
end
