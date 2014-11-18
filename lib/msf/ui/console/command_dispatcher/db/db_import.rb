module Msf::Ui::Console::CommandDispatcher::Db::DbImport
  #
  # Generic import that automatically detects the file type
  #
  def cmd_db_import(*args)
    return unless active?
    ::ActiveRecord::Base.connection_pool.with_connection {
      if args.include?("-h") || !(args && args.length > 0)
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
            framework.db.import_file(:filename => filename) do |type, data|
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

  def cmd_db_import_tabs(str, words)
    tab_complete_filenames(str, words)
  end
end
