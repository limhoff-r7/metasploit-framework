module Msf::Ui::Console::CommandDispatcher::Db::DbVulns
  # :category: Deprecated Commands
  def cmd_db_vulns(*args)
    deprecated_cmd(:vulns, *args)
  end

  # :category: Deprecated Commands
  def cmd_db_vulns_help
    deprecated_help(:vulns)
  end
end
