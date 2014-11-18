module Msf::Ui::Console::CommandDispatcher::Db::Services
  def cmd_services(*args)
    return unless active?
    ::ActiveRecord::Base.connection_pool.with_connection {
      mode = :search
      onlyup = false
      output_file = nil
      set_rhosts = nil
      col_search = ['port', 'proto', 'name', 'state', 'info']
      default_columns = ::Mdm::Service.column_names.sort
      default_columns.delete_if { |v| (v[-2, 2] == "id") }

      host_ranges = []
      port_ranges = []
      rhosts = []
      delete_count = 0
      search_term = nil

      # option parsing
      while (arg = args.shift)
        case arg
        when '-a', '--add'
          mode = :add
        when '-d', '--delete'
          mode = :delete
        when '-u', '--up'
          onlyup = true
        when '-c'
          list = args.shift
          if (!list)
            print_error("Invalid column list")
            return
          end
          col_search = list.strip().split(",")
          col_search.each { |c|
            if not default_columns.include? c
              print_error("Invalid column list. Possible values are (#{default_columns.join("|")})")
              return
            end
          }
        when '-p'
          unless (arg_port_range(args.shift, port_ranges, true))
            return
          end
        when '-r'
          proto = args.shift
          if (!proto)
            print_status("Invalid protocol")
            return
          end
          proto = proto.strip
        when '-s'
          namelist = args.shift
          if (!namelist)
            print_error("Invalid name list")
            return
          end
          names = namelist.strip().split(",")
        when '-o'
          output_file = args.shift
          if (!output_file)
            print_error("Invalid output filename")
            return
          end
          output_file = ::File.expand_path(output_file)
        when '-R', '--rhosts'
          set_rhosts = true
        when '-S', '--search'
          search_term = /#{args.shift}/nmi

        when '-h', '--help'
          print_line
          print_line "Usage: services [-h] [-u] [-a] [-r <proto>] [-p <port1,port2>] [-s <name1,name2>] [-o <filename>] [addr1 addr2 ...]"
          print_line
          print_line "  -a,--add          Add the services instead of searching"
          print_line "  -d,--delete       Delete the services instead of searching"
          print_line "  -c <col1,col2>    Only show the given columns"
          print_line "  -h,--help         Show this help information"
          print_line "  -s <name1,name2>  Search for a list of service names"
          print_line "  -p <port1,port2>  Search for a list of ports"
          print_line "  -r <protocol>     Only show [tcp|udp] services"
          print_line "  -u,--up           Only show services which are up"
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

      ports = port_ranges.flatten.uniq

      if mode == :add
        # Can only deal with one port and one service name at a time
        # right now.  Them's the breaks.
        if ports.length != 1
          print_error("Exactly one port required")
          return
        end
        host_ranges.each do |range|
          range.each do |addr|
            host = framework.db.find_or_create_host(:host => addr)
            next if not host
            info = {
                :host => host,
                :port => ports.first.to_i
            }
            info[:proto] = proto.downcase if proto
            info[:name] = names.first.downcase if names and names.first

            svc = framework.db.find_or_create_service(info)
            print_status("Time: #{svc.created_at} Service: host=#{svc.host.address} port=#{svc.port} proto=#{svc.proto} name=#{svc.name}")
          end
        end
        return
      end

      # If we got here, we're searching.  Delete implies search
      col_names = default_columns
      if col_search
        col_names = col_search
      end
      tbl = Rex::Ui::Text::Table.new({
                                         'Header' => "Services",
                                         'Columns' => ['host'] + col_names,
                                     })

      # Sentinal value meaning all
      host_ranges.push(nil) if host_ranges.empty?
      ports = nil if ports.empty?

      each_host_range_chunk(host_ranges) do |host_search|
        framework.db.services(framework.db.workspace, onlyup, proto, host_search, ports, names).each do |service|

          host = service.host
          if search_term
            next unless (
            host.attribute_names.any? { |a| host[a.intern].to_s.match(search_term) } or
                service.attribute_names.any? { |a| service[a.intern].to_s.match(search_term) }
            )
          end

          columns = [host.address] + col_names.map { |n| service[n].to_s || "" }
          tbl << columns
          if set_rhosts
            addr = (host.scope ? host.address + '%' + host.scope : host.address)
            rhosts << addr
          end

          if (mode == :delete)
            service.destroy
            delete_count += 1
          end
        end
      end

      print_line
      if (output_file == nil)
        print_line(tbl.to_s)
      else
        # create the output file
        ::File.open(output_file, "wb") { |f| f.write(tbl.to_csv) }
        print_status("Wrote services to #{output_file}")
      end

      # Finally, handle the case where the user wants the resulting list
      # of hosts to go into RHOSTS.
      set_rhosts_from_addrs(rhosts.uniq) if set_rhosts

      print_status("Deleted #{delete_count} services") if delete_count > 0

    }
  end

  def cmd_services_help
    # Like cmd_hosts, use "-h" instead of recreating the column list
    # here
    cmd_services("-h")
  end
end
