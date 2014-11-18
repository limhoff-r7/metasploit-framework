module Msf::Ui::Console::CommandDispatcher::Db::Creds
  #
  # Can return return active or all, on a certain host or range, on a
  # certain port or range, and/or on a service name.
  #
  def cmd_creds(*args)
    return unless active?

    # Short-circuit help
    if args.delete "-h"
      cmd_creds_help
      return
    end

    subcommand = args.shift
    case subcommand
    when "add-ntlm"
      creds_add_ntlm_hash(*args)
    when "add-password"
      creds_add_password(*args)
    when "add-hash"
      creds_add_non_replayable_hash(*args)
    when "add-ssh-key"
      creds_add_ssh_key(*args)
    else
      # then it's not actually a subcommand
      args.unshift(subcommand) if subcommand
      creds_search(*args)
    end

  end

  def cmd_creds_help
    print_line
    print_line "With no sub-command, list credentials. If an address range is"
    print_line "given, show only credentials with logins on hosts within that"
    print_line "range."

    print_line
    print_line "Usage - Listing credentials:"
    print_line "  creds [filter options] [address range]"
    print_line
    print_line "Usage - Adding credentials:"
    print_line "  creds add-ntlm <user> <ntlm hash> [domain]"
    print_line "  creds add-password <user> <password> [realm] [realm-type]"
    print_line "  creds add-ssh-key <user> </path/to/id_rsa> [realm-type]"
    print_line "Where [realm type] can be one of:"
    Metasploit::Model::Realm::Key::SHORT_NAMES.each do |short, description|
      print_line "  #{short} - #{description}"
    end

    print_line
    print_line "General options"
    print_line "  -h,--help             Show this help information"
    print_line "  -o <file>             Send output to a file in csv format"
    print_line
    print_line "Filter options for listing"
    print_line "  -P,--password <regex> List passwords that match this regex"
    print_line "  -p,--port <portspec>  List creds with logins on services matching this port spec"
    print_line "  -s <svc names>        List creds matching comma-separated service names"
    print_line "  -u,--user <regex>     List users that match this regex"

    print_line
    print_line "Examples, listing:"
    print_line "  creds               # Default, returns all credentials"
    print_line "  creds 1.2.3.4/24    # nmap host specification"
    print_line "  creds -p 22-25,445  # nmap port specification"
    print_line "  creds -s ssh,smb    # All creds associated with a login on SSH or SMB services"
    print_line

    print_line
    print_line "Examples, adding:"
    print_line "  # Add a user with an NTLMHash"
    print_line "  creds add-ntlm alice 5cfe4c82d9ab8c66590f5b47cd6690f1:978a2e2e1dec9804c6b936f254727f9a"
    print_line "  # Add a user with a blank password and a domain"
    print_line "  creds add-password bob '' contosso"
    print_line "  # Add a user with an SSH key"
    print_line "  creds add-ssh-key root /root/.ssh/id_rsa"
    print_line
  end

  def cmd_creds_tabs(str, words)
    case words.length
    when 1
      # subcommands
      tabs = ['add-ntlm', 'add-password', 'add-hash', 'add-ssh-key',]
    when 2
      tabs = if words[1] == 'add-ssh-key'
               tab_complete_filenames(str, words)
             else
               []
             end
      #when 5
      #  tabs = Metasploit::Model::Realm::Key::SHORT_NAMES.keys
    else
      tabs = []
    end
    return tabs
  end

  private

  # @param private_type [Symbol] See `Metasploit::Credential::Creation#create_credential`
  # @param username [String]
  # @param password [String]
  # @param realm [String]
  # @param realm_type [String] A key in `Metasploit::Model::Realm::Key::SHORT_NAMES`
  def creds_add(private_type, username, password=nil, realm=nil, realm_type=nil)
    cred_data = {
        username: username,
        private_data: password,
        private_type: private_type,
        workspace_id: framework.db.workspace,
        origin_type: :import,
        filename: "msfconsole"
    }
    if realm.present?
      if realm_type.present?
        realm_key = Metasploit::Model::Realm::Key::SHORT_NAMES[realm_type]
        if realm_key.nil?
          valid = Metasploit::Model::Realm::Key::SHORT_NAMES.keys.map { |n| "'#{n}'" }.join(", ")
          print_error("Invalid realm type: #{realm_type}. Valid values: #{valid}")
          return
        end
      end
      realm_key ||= Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
      cred_data.merge!(
          realm_value: realm,
          realm_key: realm_key
      )
    end

    begin
      create_credential(cred_data)
    rescue ActiveRecord::RecordInvalid => e
      print_error("Failed to add #{private_type}: #{e}")
    end
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

  def creds_search(*args)
    host_ranges = []
    port_ranges = []
    svcs = []

    #cred_table_columns = [ 'host', 'port', 'user', 'pass', 'type', 'proof', 'active?' ]
    cred_table_columns = ['host', 'service', 'public', 'private', 'realm', 'private_type']
    user = nil
    delete_count = 0

    while (arg = args.shift)
      case arg
      when '-o'
        output_file = args.shift
        if (!output_file)
          print_error("Invalid output filename")
          return
        end
        output_file = ::File.expand_path(output_file)
      when "-p", "--port"
        unless (arg_port_range(args.shift, port_ranges, true))
          return
        end
      when "-t", "--type"
        ptype = args.shift
        if (!ptype)
          print_error("Argument required for -t")
          return
        end
      when "-s", "--service"
        service = args.shift
        if (!service)
          print_error("Argument required for -s")
          return
        end
        svcs = service.split(/[\s]*,[\s]*/)
      when "-P", "--password"
        pass = args.shift
        if (!pass)
          print_error("Argument required for -P")
          return
        end
      when "-u", "--user"
        user = args.shift
        if (!user)
          print_error("Argument required for -u")
          return
        end
      when "-d"
        mode = :delete
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(arg, host_ranges))
          return
        end
      end
    end

    # If we get here, we're searching.  Delete implies search
    if user
      user_regex = Regexp.compile(user)
    end
    if pass
      pass_regex = Regexp.compile(pass)
    end

    # normalize
    ports = port_ranges.flatten.uniq
    svcs.flatten!
    tbl_opts = {
        'Header' => "Credentials",
        'Columns' => cred_table_columns
    }

    tbl = Rex::Ui::Text::Table.new(tbl_opts)

    ::ActiveRecord::Base.connection_pool.with_connection {
      query = Metasploit::Credential::Core.where(
          workspace_id: framework.db.workspace,
      )

      query.each do |core|

        # Exclude creds that don't match the given user
        if user_regex.present? && !core.public.username.match(user_regex)
          next
        end

        # Exclude creds that don't match the given pass
        if pass_regex.present? && !core.private.data.match(pass_regex)
          next
        end

        if core.logins.empty?
          # Skip cores that don't have any logins if the user specified a
          # filter based on host, port, or service name
          next if host_ranges.any? || ports.any? || svcs.any?

          tbl << [
              "", # host
              "", # port
              core.public,
              core.private,
              core.realm,
              core.private ? core.private.class.model_name.human : "",
          ]
        else
          core.logins.each do |login|
            if svcs.present? && !svcs.include?(login.service.name)
              next
            end

            if ports.present? && !ports.include?(login.service.port)
              next
            end

            # If none of this Core's associated Logins is for a host within
            # the user-supplied RangeWalker, then we don't have any reason to
            # print it out. However, we treat the absence of ranges as meaning
            # all hosts.
            if host_ranges.present? && !host_ranges.any? { |range| range.include?(login.service.host.address) }
              next
            end
            row = [login.service.host.address]
            if login.service.name.present?
              row << "#{login.service.port}/#{login.service.proto} (#{login.service.name})"
            else
              row << "#{login.service.port}/#{login.service.proto}"
            end

            row += [
                core.public,
                core.private,
                core.realm,
                core.private ? core.private.class.model_name.human : "",
            ]
            tbl << row
          end
        end
        if mode == :delete
          core.destroy
          delete_count += 1
        end
      end

      if output_file.nil?
        print_line(tbl.to_s)
      else
        # create the output file
        ::File.open(output_file, "wb") { |f| f.write(tbl.to_csv) }
        print_status("Wrote creds to #{output_file}")
      end

      print_status("Deleted #{delete_count} creds") if delete_count > 0
    }
  end
end
