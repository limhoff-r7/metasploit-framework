module Msf::Ui::Console::CommandDispatcher::Db::DbStatus
  #
  # Is everything working?
  #
  def cmd_db_status(*args)
    return if not db_check_driver

    if framework.db.connection_established?
      cdb = ""
      ::ActiveRecord::Base.connection_pool.with_connection { |conn|
        if conn.respond_to? :current_database
          cdb = conn.current_database
        end
      }
      print_status("#{framework.db.driver} connected to #{cdb}")
    else
      print_status("#{framework.db.driver} selected, no connection")
    end
  end
end
