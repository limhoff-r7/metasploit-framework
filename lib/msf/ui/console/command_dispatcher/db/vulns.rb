module Msf::Ui::Console::CommandDispatcher::Db::Vulns
  def cmd_vulns(*args)
    return unless active?
    ::ActiveRecord::Base.connection_pool.with_connection {

      host_ranges = []
      port_ranges = []
      svcs = []
      search_term = nil
      show_info = false

      # Short-circuit help
      if args.delete "-h"
        cmd_vulns_help
        return
      end

      while (arg = args.shift)
        case arg
          #when "-a","--add"
          #	mode = :add
          #when "-d"
          #	mode = :delete
        when "-h"
          cmd_vulns_help
          return
        when "-p", "--port"
          unless (arg_port_range(args.shift, port_ranges, true))
            return
          end
        when "-s", "--service"
          service = args.shift
          if (!service)
            print_error("Argument required for -s")
            return
          end
          svcs = service.split(/[\s]*,[\s]*/)
        when '-S', '--search'
          search_term = /#{args.shift}/nmi
        when '-i', '--info'
          show_info = true
        else
          # Anything that wasn't an option is a host to search for
          unless (arg_host_range(arg, host_ranges))
            return
          end
        end
      end

      # normalize
      host_ranges.push(nil) if host_ranges.empty?
      ports = port_ranges.flatten.uniq
      svcs.flatten!

      each_host_range_chunk(host_ranges) do |host_search|
        framework.db.hosts(framework.db.workspace, false, host_search).each do |host|
          host.vulns.each do |vuln|
            if search_term
              next unless (
              vuln.host.attribute_names.any? { |a| vuln.host[a.intern].to_s.match(search_term) } or
                  vuln.attribute_names.any? { |a| vuln[a.intern].to_s.match(search_term) }
              )
            end
            reflist = vuln.refs.map { |r| r.name }
            if (vuln.service)
              # Skip this one if the user specified a port and it
              # doesn't match.
              next unless ports.empty? or ports.include? vuln.service.port
              # Same for service names
              next unless svcs.empty? or svcs.include?(vuln.service.name)
              print_status("Time: #{vuln.created_at} Vuln: host=#{host.address} name=#{vuln.name} refs=#{reflist.join(',')} #{(show_info && vuln.info) ? "info=#{vuln.info}" : ""}")

            else
              # This vuln has no service, so it can't match
              next unless ports.empty? and svcs.empty?
              print_status("Time: #{vuln.created_at} Vuln: host=#{host.address} name=#{vuln.name} refs=#{reflist.join(',')} #{(show_info && vuln.info) ? "info=#{vuln.info}" : ""}")
            end
          end
        end
      end
    }
  end

  def cmd_vulns_help
    print_line "Print all vulnerabilities in the database"
    print_line
    print_line "Usage: vulns [addr range]"
    print_line
    print_line "  -h,--help             Show this help information"
    print_line "  -p,--port <portspec>  List vulns matching this port spec"
    print_line "  -s <svc names>        List vulns matching these service names"
    print_line "  -S,--search           Search string to filter by"
    print_line "  -i,--info             Display Vuln Info"
    print_line
    print_line "Examples:"
    print_line "  vulns -p 1-65536          # only vulns with associated services"
    print_line "  vulns -p 1-65536 -s http  # identified as http on any port"
    print_line
  end
end
