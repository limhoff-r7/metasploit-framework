module Msf::Ui::Console::CommandDispatcher::Db::Loot
  def cmd_loot(*args)
    return unless active?
    ::ActiveRecord::Base.connection_pool.with_connection {
      mode = :search
      host_ranges = []
      types = nil
      delete_count = 0
      search_term = nil
      file = nil
      name = nil
      info = nil

      while (arg = args.shift)
        case arg
        when '-a', '--add'
          mode = :add
        when '-d', '--delete'
          mode = :delete
        when '-f', '--file'
          filename = args.shift
          if (!filename)
            print_error("Can't make loot with no filename")
            return
          end
          if (!File.exists?(filename) or !File.readable?(filename))
            print_error("Can't read file")
            return
          end
        when '-i', '--info'
          info = args.shift
          if (!info)
            print_error("Can't make loot with no info")
            return
          end
        when '-t'
          typelist = args.shift
          if (!typelist)
            print_error("Invalid type list")
            return
          end
          types = typelist.strip().split(",")
        when '-S', '--search'
          search_term = /#{args.shift}/nmi
        when '-h', '--help'
          cmd_loot_help
          return
        else
          # Anything that wasn't an option is a host to search for
          unless (arg_host_range(arg, host_ranges))
            return
          end
        end
      end

      tbl = Rex::Ui::Text::Table.new({
                                         'Header' => "Loot",
                                         'Columns' => ['host', 'service', 'type', 'name', 'content', 'info', 'path'],
                                     })

      # Sentinal value meaning all
      host_ranges.push(nil) if host_ranges.empty?

      if mode == :add
        if info.nil?
          print_error("Info required")
          return
        end
        if filename.nil?
          print_error("Loot file required")
          return
        end
        if types.nil? or types.size != 1
          print_error("Exactly one loot type is required")
          return
        end
        type = types.first
        name = File.basename(filename)
        host_ranges.each do |range|
          range.each do |host|
            file = File.open(filename, "rb")
            contents = file.read
            lootfile = framework.db.find_or_create_loot(:type => type, :host => host, :info => info, :data => contents, :path => filename, :name => name)
            print_status("Added loot for #{host} (#{lootfile})")
          end
        end
        return
      end

      each_host_range_chunk(host_ranges) do |host_search|
        framework.db.hosts(framework.db.workspace, false, host_search).each do |host|
          host.loots.each do |loot|
            next if (types and types.index(loot.ltype).nil?)
            if search_term
              next unless (
              loot.attribute_names.any? { |a| loot[a.intern].to_s.match(search_term) } or
                  loot.host.attribute_names.any? { |a| loot.host[a.intern].to_s.match(search_term) }
              )
            end
            row = []
            row.push((loot.host ? loot.host.address : ""))
            if (loot.service)
              svc = (loot.service.name ? loot.service.name : "#{loot.service.port}/#{loot.service.proto}")
              row.push svc
            else
              row.push ""
            end
            row.push(loot.ltype)
            row.push(loot.name || "")
            row.push(loot.content_type)
            row.push(loot.info || "")
            row.push(loot.path)

            tbl << row
            if (mode == :delete)
              loot.destroy
              delete_count += 1
            end
          end
        end
      end

      # Handle hostless loot
      if host_ranges.compact.empty? # Wasn't a host search
        hostless_loot = framework.db.loots.find_all_by_host_id(nil)
        hostless_loot.each do |loot|
          row = []
          row.push("")
          row.push("")
          row.push(loot.ltype)
          row.push(loot.name || "")
          row.push(loot.content_type)
          row.push(loot.info || "")
          row.push(loot.path)
          tbl << row
          if (mode == :delete)
            loot.destroy
            delete_count += 1
          end
        end
      end

      print_line
      print_line(tbl.to_s)
      print_status("Deleted #{delete_count} loots") if delete_count > 0
    }
  end

  def cmd_loot_help
    print_line "Usage: loot <options>"
    print_line " Info: loot [-h] [addr1 addr2 ...] [-t <type1,type2>]"
    print_line "  Add: loot -f [fname] -i [info] -a [addr1 addr2 ...] [-t [type]"
    print_line "  Del: loot -d [addr1 addr2 ...]"
    print_line
    print_line "  -a,--add          Add loot to the list of addresses, instead of listing"
    print_line "  -d,--delete       Delete *all* loot matching host and type"
    print_line "  -f,--file         File with contents of the loot to add"
    print_line "  -i,--info         Info of the loot to add"
    print_line "  -t <type1,type2>  Search for a list of types"
    print_line "  -h,--help         Show this help information"
    print_line "  -S,--search       Search string to filter by"
    print_line
  end
end
