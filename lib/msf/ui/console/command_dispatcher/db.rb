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
  autoload :Hosts
  autoload :Loot
  autoload :Notes
  autoload :Services
  autoload :Vulns
  autoload :Workspace

  include Msf::Ui::Console::CommandDispatcher::Db::Creds
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

  def creds_add_non_replayable_hash(*args)
    creds_add(:non_replayable_hash, *args)
  end

  def creds_add_ntlm_hash(*args)
    creds_add(:ntlm_hash, *args)
  end

  def creds_add_password(*args)
    creds_add(:password, *args)
  end

  def creds_add_ssh_key(username, *args)
    key_file, realm = args
    begin
      key_data = File.read(key_file)
    rescue ::Errno::EACCES, ::Errno::ENOENT => e
      print_error("Failed to add ssh key: #{e}")
    else
      creds_add(:ssh_key, username, key_data, realm)
    end
  end

  # :category: Deprecated Commands
  def cmd_db_hosts_help; deprecated_help(:hosts); end
  # :category: Deprecated Commands
  def cmd_db_notes_help; deprecated_help(:notes); end
  # :category: Deprecated Commands
  def cmd_db_vulns_help; deprecated_help(:vulns); end
  # :category: Deprecated Commands
  def cmd_db_services_help; deprecated_help(:services); end
  # :category: Deprecated Commands
  def cmd_db_autopwn_help; deprecated_help; end
  # :category: Deprecated Commands
  def cmd_db_driver_help; deprecated_help; end

  # :category: Deprecated Commands
  def cmd_db_hosts(*args); deprecated_cmd(:hosts, *args); end
  # :category: Deprecated Commands
  def cmd_db_notes(*args); deprecated_cmd(:notes, *args); end
  # :category: Deprecated Commands
  def cmd_db_vulns(*args); deprecated_cmd(:vulns, *args); end
  # :category: Deprecated Commands
  def cmd_db_services(*args); deprecated_cmd(:services, *args); end
  # :category: Deprecated Commands
  def cmd_db_autopwn(*args); deprecated_cmd; end

  #
  # :category: Deprecated Commands
  #
  # This one deserves a little more explanation than standard deprecation
  # warning, so give the user a better understanding of what's going on.
  #
  def cmd_db_driver(*args)
    deprecated_cmd
    print_line
    print_line "Because Metasploit no longer supports databases other than the default"
    print_line "PostgreSQL, there is no longer a need to set the driver. Thus db_driver"
    print_line "is not useful and its functionality has been removed. Usually Metasploit"
    print_line "will already have connected to the database; check db_status to see."
    print_line
    cmd_db_status
  end

  def cmd_db_import_tabs(str, words)
    tab_complete_filenames(str, words)
  end

  def cmd_db_import_help
    print_line "Usage: db_import <filename> [file2...]"
    print_line
    print_line "Filenames can be globs like *.xml, or **/*.xml which will search recursively"
    print_line "Currently supported file types include:"
    print_line "    Acunetix"
    print_line "    Amap Log"
    print_line "    Amap Log -m"
    print_line "    Appscan"
    print_line "    Burp Session XML"
    print_line "    CI"
    print_line "    Foundstone"
    print_line "    FusionVM XML"
    print_line "    IP Address List"
    print_line "    IP360 ASPL"
    print_line "    IP360 XML v3"
    print_line "    Libpcap Packet Capture"
    print_line "    Metasploit PWDump Export"
    print_line "    Metasploit XML"
    print_line "    Metasploit Zip Export"
    print_line "    Microsoft Baseline Security Analyzer"
    print_line "    NeXpose Simple XML"
    print_line "    NeXpose XML Report"
    print_line "    Nessus NBE Report"
    print_line "    Nessus XML (v1)"
    print_line "    Nessus XML (v2)"
    print_line "    NetSparker XML"
    print_line "    Nikto XML"
    print_line "    Nmap XML"
    print_line "    OpenVAS Report"
    print_line "    OpenVAS XML"
    print_line "    Outpost24 XML"
    print_line "    Qualys Asset XML"
    print_line "    Qualys Scan XML"
    print_line "    Retina XML"
    print_line "    Spiceworks CSV Export"
    print_line "    Wapiti XML"
    print_line
  end

  #
  # Generic import that automatically detects the file type
  #
  def cmd_db_import(*args)
    return unless active?
  ::ActiveRecord::Base.connection_pool.with_connection {
    if args.include?("-h") || ! (args && args.length > 0)
      cmd_db_import_help
      return
    end
    args.each { |glob|
      files = ::Dir.glob(::File.expand_path(glob))
      if files.empty?
        print_error("No such file #{glob}")
        next
      end
      files.each { |filename|
        if (not ::File.readable?(filename))
          print_error("Could not read file #{filename}")
          next
        end
        begin
          warnings = 0
          framework.db.import_file(:filename => filename) do |type,data|
            case type
            when :debug
              print_error("DEBUG: #{data.inspect}")
            when :vuln
              inst = data[1] == 1 ? "instance" : "instances"
              print_status("Importing vulnerability '#{data[0]}' (#{data[1]} #{inst})")
            when :filetype
              print_status("Importing '#{data}' data")
            when :parser
              print_status("Import: Parsing with '#{data}'")
            when :address
              print_status("Importing host #{data}")
            when :service
              print_status("Importing service #{data}")
            when :msf_loot
              print_status("Importing loot #{data}")
            when :msf_task
              print_status("Importing task #{data}")
            when :msf_report
              print_status("Importing report #{data}")
            when :pcap_count
              print_status("Import: #{data} packets processed")
            when :record_count
              print_status("Import: #{data[1]} records processed")
            when :warning
              print_error
              data.split("\n").each do |line|
                print_error(line)
              end
              print_error
              warnings += 1
            end
          end
          print_status("Successfully imported #{filename}")

          print_error("Please note that there were #{warnings} warnings") if warnings > 1
          print_error("Please note that there was one warning") if warnings == 1

        rescue Msf::DBImportError
          print_error("Failed to import #{filename}: #{$!}")
          elog("Failed to import #{filename}: #{$!.class}: #{$!}")
          dlog("Call stack: #{$@.join("\n")}", LEV_3)
          next
        rescue REXML::ParseException => e
          print_error("Failed to import #{filename} due to malformed XML:")
          print_error("#{e.class}: #{e}")
          elog("Failed to import #{filename}: #{e.class}: #{e}")
          dlog("Call stack: #{$@.join("\n")}", LEV_3)
          next
        end
      }
    }
  }
  end

  def cmd_db_export_help
    # Like db_hosts and db_services, this creates a list of columns, so
    # use its -h
    cmd_db_export("-h")
  end

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
      when '-h','--help'
        print_line "Usage:"
        print_line "    db_export -f <format> [-a] [filename]"
        print_line "    Format can be one of: #{export_formats.join(", ")}"
      when '-f','--format'
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

    exporter.send("to_#{format}_file".intern,output) do |mtype, mstatus, mname|
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

  #
  # Import Nmap data from a file
  #
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

  def cmd_db_connect_help
    # Help is specific to each driver
    cmd_db_connect("-h")
  end

  def cmd_db_connect(*args)
    return if not db_check_driver
    if (args[0] == "-y")
      if (args[1] and not ::File.exists? ::File.expand_path(args[1]))
        print_error("File not found")
        return
      end
      file = args[1] || ::File.join(Msf::Config.get_config_root, "database.yml")
      file = ::File.expand_path(file)
      if (::File.exists? file)
        db = YAML.load(::File.read(file))['production']
        framework.db.connect(db)

        if framework.db.active and not framework.db.modules_cached
          print_status("Rebuilding the module cache in the background...")
          framework.threads.spawn("ModuleCacheRebuild", true) do
            framework.db.update_all_module_details
          end
        end

        return
      end
    end
    meth = "db_connect_#{framework.db.driver}"
    if(self.respond_to?(meth))
      self.send(meth, *args)
      if framework.db.active and not framework.db.modules_cached
        print_status("Rebuilding the module cache in the background...")
        framework.threads.spawn("ModuleCacheRebuild", true) do
          framework.db.update_all_module_details
        end
      end
    else
      print_error("This database driver #{framework.db.driver} is not currently supported")
    end
  end

  def cmd_db_disconnect_help
    print_line "Usage: db_disconnect"
    print_line
    print_line "Disconnect from the database."
    print_line
  end

  def cmd_db_disconnect(*args)
    return if not db_check_driver

    if(args[0] and (args[0] == "-h" || args[0] == "--help"))
      cmd_db_disconnect_help
      return
    end

    if (framework.db)
      framework.db.disconnect()
    end
  end

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

  def db_find_tools(tools)
    missed  = []
    tools.each do |name|
      if(! Rex::FileUtils.find_full_path(name))
        missed << name
      end
    end
    if(not missed.empty?)
      print_error("This database command requires the following tools to be installed: #{missed.join(", ")}")
      return
    end
    true
  end

  #
  # Database management: Postgres
  #

  #
  # Connect to an existing Postgres database
  #
  def db_connect_postgresql(*args)
    if(args[0] == nil or args[0] == "-h" or args[0] == "--help")
      print_status("   Usage: db_connect <user:pass>@<host:port>/<database>")
      print_status("      OR: db_connect -y [path/to/database.yml]")
      print_status("Examples:")
      print_status("       db_connect user@metasploit3")
      print_status("       db_connect user:pass@192.168.0.2/metasploit3")
      print_status("       db_connect user:pass@192.168.0.2:1500/metasploit3")
      return
    end

    info = db_parse_db_uri_postgresql(args[0])
    opts = { 'adapter' => 'postgresql' }

    opts['username'] = info[:user] if (info[:user])
    opts['password'] = info[:pass] if (info[:pass])
    opts['database'] = info[:name]
    opts['host'] = info[:host] if (info[:host])
    opts['port'] = info[:port] if (info[:port])

    opts['pass'] ||= ''

    # Do a little legwork to find the real database socket
    if(! opts['host'])
      while(true)
        done = false
        dirs = %W{ /var/run/postgresql /tmp }
        dirs.each do |dir|
          if(::File.directory?(dir))
            d = ::Dir.new(dir)
            d.entries.grep(/^\.s\.PGSQL.(\d+)$/).each do |ent|
              opts['port'] = ent.split('.')[-1].to_i
              opts['host'] = dir
              done = true
              break
            end
          end
          break if done
        end
        break
      end
    end

    # Default to loopback
    if(! opts['host'])
      opts['host'] = '127.0.0.1'
    end

    if (not framework.db.connect(opts))
      raise RuntimeError.new("Failed to connect to the database: #{framework.db.error}")
    end
  end

  def db_parse_db_uri_postgresql(path)
    res = {}
    if (path)
      auth, dest = path.split('@')
      (dest = auth and auth = nil) if not dest
      res[:user],res[:pass] = auth.split(':') if auth
      targ,name = dest.split('/')
      (name = targ and targ = nil) if not name
      res[:host],res[:port] = targ.split(':') if targ
    end
    res[:name] = name || 'metasploit3'
    res
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
