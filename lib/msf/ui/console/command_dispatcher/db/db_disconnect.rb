module Msf::Ui::Console::CommandDispatcher::Db::DbDisconnect
  def cmd_db_disconnect(*args)
    return if not db_check_driver

    if (args[0] and (args[0] == "-h" || args[0] == "--help"))
      cmd_db_disconnect_help
      return
    end

    if (framework.db)
      framework.db.disconnect()
    end
  end

  def cmd_db_disconnect_help
    print_line "Usage: db_disconnect"
    print_line
    print_line "Disconnect from the database."
    print_line
  end
end
