module Msf::Ui::Console::CommandDispatcher::Db::DbConnect
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
    include_protected_and_private = true

    if (self.respond_to?(meth, include_protected_and_private))
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

  def cmd_db_connect_help
    # Help is specific to each driver
    cmd_db_connect("-h")
  end

  private

  #
  # Database management: Postgres
  #
  #
  # Connect to an existing Postgres database
  #
  def db_connect_postgresql(*args)
    if (args[0] == nil or args[0] == "-h" or args[0] == "--help")
      print_status("   Usage: db_connect <user:pass>@<host:port>/<database>")
      print_status("      OR: db_connect -y [path/to/database.yml]")
      print_status("Examples:")
      print_status("       db_connect user@metasploit3")
      print_status("       db_connect user:pass@192.168.0.2/metasploit3")
      print_status("       db_connect user:pass@192.168.0.2:1500/metasploit3")
      return
    end

    info = db_parse_db_uri_postgresql(args[0])
    opts = {'adapter' => 'postgresql'}

    opts['username'] = info[:user] if (info[:user])
    opts['password'] = info[:pass] if (info[:pass])
    opts['database'] = info[:name]
    opts['host'] = info[:host] if (info[:host])
    opts['port'] = info[:port] if (info[:port])

    opts['pass'] ||= ''

    # Do a little legwork to find the real database socket
    if (!opts['host'])
      while (true)
        done = false
        dirs = %W{ /var/run/postgresql /tmp }
        dirs.each do |dir|
          if (::File.directory?(dir))
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
    if (!opts['host'])
      opts['host'] = '127.0.0.1'
    end

    if (not framework.db.connect(opts))
      raise RuntimeError.new("Failed to connect to the database: #{framework.db.error}")
    end
  end
end
