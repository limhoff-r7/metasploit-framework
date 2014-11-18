module Msf::Ui::Console::CommandDispatcher::Db::DbNotes
  # :category: Deprecated Commands
  def cmd_db_notes(*args)
    deprecated_cmd(:notes, *args)
  end

  # :category: Deprecated Commands
  def cmd_db_notes_help
    deprecated_help(:notes)
  end
end
