# -*- coding: binary -*-

require 'rexml/document'
require 'rex/parser/nmap_xml'
require 'msf/core/db_export'

module Msf
module Ui
module Console
module CommandDispatcher

class Db
  extend ActiveSupport::Autoload

  autoload :Creds
  autoload :DbAutopwn
  autoload :DbConnect
  autoload :DbDisconnect
  autoload :DbDriver
  autoload :DbExport
  autoload :DbHosts
  autoload :DbImport
  autoload :DbRebuildCache
  autoload :Hosts
  autoload :Loot
  autoload :Notes
  autoload :Services
  autoload :Vulns
  autoload :Workspace

  include Msf::Ui::Console::CommandDispatcher::Db::Creds
  include Msf::Ui::Console::CommandDispatcher::Db::DbAutopwn
  include Msf::Ui::Console::CommandDispatcher::Db::DbConnect
  include Msf::Ui::Console::CommandDispatcher::Db::DbDisconnect
  include Msf::Ui::Console::CommandDispatcher::Db::DbDriver
  include Msf::Ui::Console::CommandDispatcher::Db::DbExport
  include Msf::Ui::Console::CommandDispatcher::Db::DbHosts
  include Msf::Ui::Console::CommandDispatcher::Db::DbImport
  include Msf::Ui::Console::CommandDispatcher::Db::DbRebuildCache
  include Msf::Ui::Console::CommandDispatcher::Db::Hosts
  include Msf::Ui::Console::CommandDispatcher::Db::Loot
  include Msf::Ui::Console::CommandDispatcher::Db::Notes
  include Msf::Ui::Console::CommandDispatcher::Db::Services
  include Msf::Ui::Console::CommandDispatcher::Db::Vulns
  include Msf::Ui::Console::CommandDispatcher::Db::Workspace

  require 'tempfile'

  include Msf::Ui::Console::CommandDispatcher

  # TODO: Not thrilled about including this entire module for just store_local.
  include Msf::Auxiliary::Report

  include Metasploit::Credential::Creation

  #
  # The dispatcher's name.
  #
  def name
    "Database Backend"
  end

  #
  # Returns the hash of commands supported by this dispatcher.
  #
  def commands
    base = {
      "db_connect"    => "Connect to an existing database",
      "db_disconnect" => "Disconnect from the current database instance",
      "db_status"     => "Show the current database status",
    }

    more = {
      "workspace"     => "Switch between database workspaces",
      "hosts"         => "List all hosts in the database",
      "services"      => "List all services in the database",
      "vulns"         => "List all vulnerabilities in the database",
      "notes"         => "List all notes in the database",
      "loot"          => "List all loot in the database",
      "creds"         => "List all credentials in the database",
      "db_import"     => "Import a scan result file (filetype will be auto-detected)",
      "db_export"     => "Export a file containing the contents of the database",
      "db_nmap"       => "Executes nmap and records the output automatically",
      "db_rebuild_cache" => "Rebuilds the database-stored module cache"
    }

    # Always include commands that only make sense when connected.
    # This avoids the problem of them disappearing unexpectedly if the
    # database dies or times out.  See #1923
    base.merge(more)
  end

  def deprecated_commands
    [
      "db_autopwn",
      "db_driver",
      "db_hosts",
      "db_notes",
      "db_services",
      "db_vulns",
    ]
  end

  #
  # Returns true if the db is connected, prints an error and returns
  # false if not.
  #
  # All commands that require an active database should call this before
  # doing anything.
  #
  def active?
    if not framework.db.active
      print_error("Database not connected")
      return false
    end
    true
  end

  # :category: Deprecated Commands
  def cmd_db_notes_help; deprecated_help(:notes); end
  # :category: Deprecated Commands
  def cmd_db_vulns_help; deprecated_help(:vulns); end
  # :category: Deprecated Commands
  def cmd_db_services_help; deprecated_help(:services); end

  # :category: Deprecated Commands
  def cmd_db_notes(*args); deprecated_cmd(:notes, *args); end
  # :category: Deprecated Commands
  def cmd_db_vulns(*args); deprecated_cmd(:vulns, *args); end
  # :category: Deprecated Commands
  def cmd_db_services(*args); deprecated_cmd(:services, *args); end

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
    if(Rex::Compat.is_cygwin and nmap =~ /cygdrive/)
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

      temp_nmap_threads.map {|t| t.join rescue nil}
      nmap_pipe.each {|p| p.close rescue nil}
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

  #
  # Store some locally-generated data as a file, similiar to store_loot.
  #
  def report_store_local(ltype=nil, ctype=nil, data=nil, filename=nil)
    store_local(ltype,ctype,data,filename)
  end

  #
  # Database management
  #
  def db_check_driver
    if(not framework.db.driver)
      print_error("No database driver installed. Try 'gem install pg'")
      return false
    end
    true
  end

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

  #
  # Set RHOSTS in the +active_module+'s (or global if none) datastore from an array of addresses
  #
  # This stores all the addresses to a temporary file and utilizes the
  # <pre>file:/tmp/filename</pre> syntax to confer the addrs.  +rhosts+
  # should be an Array.  NOTE: the temporary file is *not* deleted
  # automatically.
  #
  def set_rhosts_from_addrs(rhosts)
    if rhosts.empty?
      print_status("The list is empty, cowardly refusing to set RHOSTS")
      return
    end
    if active_module
      mydatastore = active_module.datastore
    else
      # if there is no module in use set the list to the global variable
      mydatastore = self.framework.datastore
    end

    if rhosts.length > 5
      # Lots of hosts makes 'show options' wrap which is difficult to
      # read, store to a temp file
      rhosts_file = Rex::Quickfile.new("msf-db-rhosts-")
      mydatastore['RHOSTS'] = 'file:'+rhosts_file.path
      # create the output file and assign it to the RHOSTS variable
      rhosts_file.write(rhosts.join("\n")+"\n")
      rhosts_file.close
    else
      # For short lists, just set it directly
      mydatastore['RHOSTS'] = rhosts.join(" ")
    end

    print_line "RHOSTS => #{mydatastore['RHOSTS']}"
    print_line
  end

  #
  # Miscellaneous option helpers
  #

  # Parse +arg+ into a {Rex::Socket::RangeWalker} and append the result into +host_ranges+
  #
  # @note This modifies +host_ranges+ in place
  #
  # @param arg [String] The thing to turn into a RangeWalker
  # @param host_ranges [Array] The array of ranges to append
  # @param required [Boolean] Whether an empty +arg+ should be an error
  # @return [Boolean] true if parsing was successful or false otherwise
  def arg_host_range(arg, host_ranges, required=false)
    if (!arg and required)
      print_error("Missing required host argument")
      return false
    end
    begin
      rw = Rex::Socket::RangeWalker.new(arg)
    rescue
      print_error("Invalid host parameter, #{arg}.")
      return false
    end

    if rw.valid?
      host_ranges << rw
    else
      print_error("Invalid host parameter, #{arg}.")
      return false
    end
    return true
  end

  #
  # Parse +arg+ into an array of ports and append the result into +port_ranges+
  #
  # Returns true if parsing was successful or nil otherwise.
  #
  # NOTE: This modifies +port_ranges+
  #
  def arg_port_range(arg, port_ranges, required=false)
    if (!arg and required)
      print_error("Argument required for -p")
      return
    end
    begin
      port_ranges << Rex::Socket.portspec_to_portlist(arg)
    rescue
      print_error("Invalid port parameter, #{arg}.")
      return
    end
    return true
  end

  #
  # Takes +host_ranges+, an Array of RangeWalkers, and chunks it up into
  # blocks of 1024.
  #
  def each_host_range_chunk(host_ranges, &block)
    # Chunk it up and do the query in batches. The naive implementation
    # uses so much memory for a /8 that it's basically unusable (1.6
    # billion IP addresses take a rather long time to allocate).
    # Chunking has roughly the same perfomance for small batches, so
    # don't worry about it too much.
    host_ranges.each do |range|
      if range.nil? or range.length.nil?
        chunk = nil
        end_of_range = true
      else
        chunk = []
        end_of_range = false
        # Set up this chunk of hosts to search for
        while chunk.length < 1024 and chunk.length < range.length
          n = range.next_ip
          if n.nil?
            end_of_range = true
            break
          end
          chunk << n
        end
      end

      # The block will do some
      yield chunk

      # Restart the loop with the same RangeWalker if we didn't get
      # to the end of it in this chunk.
      redo unless end_of_range
    end
  end

end

end end end end
