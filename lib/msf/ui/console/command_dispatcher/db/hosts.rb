module Msf::Ui::Console::CommandDispatcher::Db::Hosts
  def cmd_hosts(*args)
    return unless active?
    ::ActiveRecord::Base.connection_pool.with_connection {
      onlyup = false
      set_rhosts = false
      mode = :search
      delete_count = 0

      rhosts = []
      host_ranges = []
      search_term = nil

      output = nil
      default_columns = ::Mdm::Host.column_names.sort
      virtual_columns = ['svcs', 'vulns', 'workspace']

      col_search = ['address', 'mac', 'name', 'os_name', 'os_flavor', 'os_sp', 'purpose', 'info', 'comments']

      default_columns.delete_if { |v| (v[-2, 2] == "id") }
      while (arg = args.shift)
        case arg
        when '-a', '--add'
          mode = :add
        when '-d', '--delete'
          mode = :delete
        when '-c'
          list = args.shift
          if (!list)
            print_error("Invalid column list")
            return
          end
          col_search = list.strip().split(",")
          col_search.each { |c|
            if not default_columns.include?(c) and not virtual_columns.include?(c)
              all_columns = default_columns + virtual_columns
              print_error("Invalid column list. Possible values are (#{all_columns.join("|")})")
              return
            end
          }
        when '-u', '--up'
          onlyup = true
        when '-o'
          output = args.shift
        when '-R', '--rhosts'
          set_rhosts = true
        when '-S', '--search'
          search_term = /#{args.shift}/nmi

        when '-h', '--help'
          print_line "Usage: hosts [ options ] [addr1 addr2 ...]"
          print_line
          print_line "OPTIONS:"
          print_line "  -a,--add          Add the hosts instead of searching"
          print_line "  -d,--delete       Delete the hosts instead of searching"
          print_line "  -c <col1,col2>    Only show the given columns (see list below)"
          print_line "  -h,--help         Show this help information"
          print_line "  -u,--up           Only show hosts which are up"
          print_line "  -o <file>         Send output to a file in csv format"
          print_line "  -R,--rhosts       Set RHOSTS from the results of the search"
          print_line "  -S,--search       Search string to filter by"
          print_line
          print_line "Available columns: #{default_columns.join(", ")}"
          print_line
          return
        else
          # Anything that wasn't an option is a host to search for
          unless (arg_host_range(arg, host_ranges))
            return
          end
        end
      end

      if col_search
        col_names = col_search
      else
        col_names = default_columns + virtual_columns
      end

      if mode == :add
        host_ranges.each do |range|
          range.each do |address|
            host = framework.db.find_or_create_host(:host => address)
            print_status("Time: #{host.created_at} Host: host=#{host.address}")
          end
        end
        return
      end

      # If we got here, we're searching.  Delete implies search
      tbl = Rex::Ui::Text::Table.new(
          {
              'Header' => "Hosts",
              'Columns' => col_names,
          })

      # Sentinal value meaning all
      host_ranges.push(nil) if host_ranges.empty?

      each_host_range_chunk(host_ranges) do |host_search|
        framework.db.hosts(framework.db.workspace, onlyup, host_search).each do |host|
          if search_term
            next unless host.attribute_names.any? { |a| host[a.intern].to_s.match(search_term) }
          end
          columns = col_names.map do |n|
            # Deal with the special cases
            if virtual_columns.include?(n)
              case n
              when "svcs";
                host.services.length
              when "vulns";
                host.vulns.length
              when "workspace";
                host.workspace.name
              end
              # Otherwise, it's just an attribute
            else
              host.attributes[n] || ""
            end
          end

          tbl << columns
          if set_rhosts
            addr = (host.scope ? host.address + '%' + host.scope : host.address)
            rhosts << addr
          end
          if mode == :delete
            host.destroy
            delete_count += 1
          end
        end
      end

      if output
        print_status("Wrote hosts to #{output}")
        ::File.open(output, "wb") { |ofd|
          ofd.write(tbl.to_csv)
        }
      else
        print_line
        print_line(tbl.to_s)
      end

      # Finally, handle the case where the user wants the resulting list
      # of hosts to go into RHOSTS.
      set_rhosts_from_addrs(rhosts.uniq) if set_rhosts

      print_status("Deleted #{delete_count} hosts") if delete_count > 0
    }
  end

  def cmd_hosts_help
    # This command does some lookups for the list of appropriate column
    # names, so instead of putting all the usage stuff here like other
    # help methods, just use it's "-h" so we don't have to recreating
    # that list
    cmd_hosts("-h")
  end
end
