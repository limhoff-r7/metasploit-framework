module Msf::Ui::Console::CommandDispatcher::Db::Notes
  def cmd_notes(*args)
    return unless active?
    ::ActiveRecord::Base.connection_pool.with_connection {
      mode = :search
      data = nil
      types = nil
      set_rhosts = false

      host_ranges = []
      rhosts = []
      search_term = nil

      while (arg = args.shift)
        case arg
        when '-a', '--add'
          mode = :add
        when '-d', '--delete'
          mode = :delete
        when '-n', '--note'
          data = args.shift
          if (!data)
            print_error("Can't make a note with no data")
            return
          end
        when '-t'
          typelist = args.shift
          if (!typelist)
            print_error("Invalid type list")
            return
          end
          types = typelist.strip().split(",")
        when '-R', '--rhosts'
          set_rhosts = true
        when '-S', '--search'
          search_term = /#{args.shift}/nmi
        when '--sort'
          sort_term = args.shift
        when '-h', '--help'
          cmd_notes_help
          return
        else
          # Anything that wasn't an option is a host to search for
          unless (arg_host_range(arg, host_ranges))
            return
          end
        end

      end

      if mode == :add
        if types.nil? or types.size != 1
          print_error("Exactly one note type is required")
          return
        end
        type = types.first
        host_ranges.each { |range|
          range.each { |addr|
            host = framework.db.find_or_create_host(:host => addr)
            break if not host
            note = framework.db.find_or_create_note(:host => host, :type => type, :data => data)
            break if not note
            print_status("Time: #{note.created_at} Note: host=#{host.address} type=#{note.ntype} data=#{note.data}")
          }
        }
        return
      end

      note_list = []
      delete_count = 0
      # No host specified - collect all notes
      if host_ranges.empty?
        note_list = framework.db.notes.dup
        # Collect notes of specified hosts
      else
        each_host_range_chunk(host_ranges) do |host_search|
          framework.db.hosts(framework.db.workspace, false, host_search).each do |host|
            note_list.concat(host.notes)
          end
        end
      end
      if search_term
        note_list.delete_if do |n|
          !n.attribute_names.any? { |a| n[a.intern].to_s.match(search_term) }
        end
      end

      # Sort the notes based on the sort_term provided
      if sort_term != nil
        sort_terms = sort_term.split(",")
        note_list.sort_by! do |note|
          orderlist = []
          sort_terms.each do |term|
            term = "ntype" if term == "type"
            term = "created_at" if term == "Time"
            if term == nil
              orderlist << ""
            elsif term == "service"
              if note.service != nil
                orderlist << make_sortable(note.service.name)
              end
            elsif term == "port"
              if note.service != nil
                orderlist << make_sortable(note.service.port)
              end
            elsif term == "output"
              orderlist << make_sortable(note.data["output"])
            elsif note.respond_to?(term)
              orderlist << make_sortable(note.send(term))
            elsif note.respond_to?(term.to_sym)
              orderlist << make_sortable(note.send(term.to_sym))
            elsif note.respond_to?("data") && note.send("data").respond_to?(term)
              orderlist << make_sortable(note.send("data").send(term))
            elsif note.respond_to?("data") && note.send("data").respond_to?(term.to_sym)
              orderlist << make_sortable(note.send("data").send(term.to_sym))
            else
              orderlist << ""
            end
          end
          orderlist
        end
      end

      # Now display them
      note_list.each do |note|
        next if (types and types.index(note.ntype).nil?)
        msg = "Time: #{note.created_at} Note:"
        if (note.host)
          host = note.host
          msg << " host=#{note.host.address}"
          if set_rhosts
            addr = (host.scope ? host.address + '%' + host.scope : host.address)
            rhosts << addr
          end
        end
        if (note.service)
          msg << " service=#{note.service.name}" if note.service.name
          msg << " port=#{note.service.port}" if note.service.port
          msg << " protocol=#{note.service.proto}" if note.service.proto
        end
        msg << " type=#{note.ntype} data=#{note.data.inspect}"
        print_status(msg)
        if mode == :delete
          note.destroy
          delete_count += 1
        end
      end

      # Finally, handle the case where the user wants the resulting list
      # of hosts to go into RHOSTS.
      set_rhosts_from_addrs(rhosts.uniq) if set_rhosts

      print_status("Deleted #{delete_count} notes") if delete_count > 0
    }
  end

  def cmd_notes_help
    print_line "Usage: notes [-h] [-t <type1,type2>] [-n <data string>] [-a] [addr range]"
    print_line
    print_line "  -a,--add                  Add a note to the list of addresses, instead of listing"
    print_line "  -d,--delete               Delete the hosts instead of searching"
    print_line "  -n,--note <data>          Set the data for a new note (only with -a)"
    print_line "  -t <type1,type2>          Search for a list of types"
    print_line "  -h,--help                 Show this help information"
    print_line "  -R,--rhosts               Set RHOSTS from the results of the search"
    print_line "  -S,--search               Regular expression to match for search"
    print_line "  --sort <field1,field2>    Fields to sort by (case sensitive)"
    print_line
    print_line "Examples:"
    print_line "  notes --add -t apps -n 'winzip' 10.1.1.34 10.1.20.41"
    print_line "  notes -t smb.fingerprint 10.1.1.34 10.1.20.41"
    print_line "  notes -S 'nmap.nse.(http|rtsp)' --sort type,output"
    print_line
  end
end
