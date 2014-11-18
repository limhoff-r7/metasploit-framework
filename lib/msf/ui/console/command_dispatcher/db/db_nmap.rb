module Msf::Ui::Console::CommandDispatcher::Db::DbNmap
  #
  # Import Nmap data from a file
  def cmd_db_nmap(*args)
    return unless active?
    ::ActiveRecord::Base.connection_pool.with_connection {
      if (args.length == 0)
        print_status("Usage: db_nmap [nmap options]")
        return
      end

      save = false
      if args.include?("save")
        save = active?
        args.delete("save")
      end

      nmap =
          Rex::FileUtils.find_full_path("nmap") ||
              Rex::FileUtils.find_full_path("nmap.exe")

      if (not nmap)
        print_error("The nmap executable could not be found")
        return
      end

      fd = Tempfile.new('dbnmap')
      fd.binmode

      fo = Tempfile.new('dbnmap')
      fo.binmode

      # When executing native Nmap in Cygwin, expand the Cygwin path to a Win32 path
      if (Rex::Compat.is_cygwin and nmap =~ /cygdrive/)
        # Custom function needed because cygpath breaks on 8.3 dirs
        tout = Rex::Compat.cygwin_to_win32(fd.path)
        fout = Rex::Compat.cygwin_to_win32(fo.path)
        args.push('-oX', tout)
        args.push('-oN', fout)
      else
        args.push('-oX', fd.path)
        args.push('-oN', fo.path)
      end

      begin
        nmap_pipe = ::Open3::popen3([nmap, "nmap"], *args)
        temp_nmap_threads = []
        temp_nmap_threads << framework.threads.spawn("db_nmap-Stdout", false, nmap_pipe[1]) do |np_1|
          np_1.each_line do |nmap_out|
            next if nmap_out.strip.empty?
            print_status("Nmap: #{nmap_out.strip}")
          end
        end

        temp_nmap_threads << framework.threads.spawn("db_nmap-Stderr", false, nmap_pipe[2]) do |np_2|
          np_2.each_line do |nmap_err|
            next if nmap_err.strip.empty?
            print_status("Nmap: '#{nmap_err.strip}'")
          end
        end

        temp_nmap_threads.map { |t| t.join rescue nil }
        nmap_pipe.each { |p| p.close rescue nil }
      rescue ::IOError
      end

      fo.close(true)
      framework.db.import_nmap_xml_file(:filename => fd.path)

      if save
        fd.rewind
        saved_path = report_store_local("nmap.scan.xml", "text/xml", fd.read, "nmap_#{Time.now.utc.to_i}")
        print_status("Saved NMAP XML results to #{saved_path}")
      end
      fd.close(true)
    }
  end

  private

  #
  # Store some locally-generated data as a file, similiar to store_loot.
  #
  def report_store_local(ltype=nil, ctype=nil, data=nil, filename=nil)
    store_local(ltype, ctype, data, filename)
  end
end
