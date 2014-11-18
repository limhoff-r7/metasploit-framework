module Msf::Ui::Console::CommandDispatcher::Db::DbServices
  # :category: Deprecated Commands
  def cmd_db_services(*args)
    deprecated_cmd(:services, *args)
  end

  # :category: Deprecated Commands
  def cmd_db_services_help
    deprecated_help(:services)
  end
end
