module Msf::Ui::Console::CommandDispatcher::Db::DbHosts
  # :category: Deprecated Commands
  def cmd_db_hosts(*args)
    deprecated_cmd(:hosts, *args)
  end

  # :category: Deprecated Commands
  def cmd_db_hosts_help
    deprecated_help(:hosts)
  end
end
