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
end
