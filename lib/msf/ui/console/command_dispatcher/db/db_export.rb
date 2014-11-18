module Msf::Ui::Console::CommandDispatcher::Db::DbExport
  #
  # Export an XML
  #
  def cmd_db_export(*args)
    return unless active?
    ::ActiveRecord::Base.connection_pool.with_connection {

      export_formats = %W{xml pwdump}
      format = 'xml'
      output = nil

      while (arg = args.shift)
        case arg
        when '-h', '--help'
          print_line "Usage:"
          print_line "    db_export -f <format> [-a] [filename]"
          print_line "    Format can be one of: #{export_formats.join(", ")}"
        when '-f', '--format'
          format = args.shift.to_s.downcase
        else
          output = arg
        end
      end

      if not output
        print_error("No output file was specified")
        return
      end

      if not export_formats.include?(format)
        print_error("Unsupported file format: #{format}")
        print_error("Unsupported file format: '#{format}'. Must be one of: #{export_formats.join(", ")}")
        return
      end

      print_status("Starting export of workspace #{framework.db.workspace.name} to #{output} [ #{format} ]...")
      exporter = ::Msf::DBManager::Export.new(framework.db.workspace)

      exporter.send("to_#{format}_file".intern, output) do |mtype, mstatus, mname|
        if mtype == :status
          if mstatus == "start"
            print_status("    >> Starting export of #{mname}")
          end
          if mstatus == "complete"
            print_status("    >> Finished export of #{mname}")
          end
        end
      end
      print_status("Finished export of workspace #{framework.db.workspace.name} to #{output} [ #{format} ]...")
    }
  end

  def cmd_db_export_help
    # Like db_hosts and db_services, this creates a list of columns, so
    # use its -h
    cmd_db_export("-h")
  end
end

