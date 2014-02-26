# -*- coding: binary -*-

###
#
# Standard API extension.
#
###
class Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher::Stdapi
  include Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher

  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/stdapi/fs'
  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/stdapi/net'
  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/stdapi/sys'
  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/stdapi/ui'
  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/stdapi/webcam'

  Klass = Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher::Stdapi

  Dispatchers =
    [
      Klass::Fs,
      Klass::Net,
      Klass::Sys,
      Klass::Ui,
      Klass::Webcam,
    ]

  #
  # Initializes an instance of the stdapi command interaction.
  #
  def initialize(shell)
    super

    Dispatchers.each { |d|
      shell.enstack_dispatcher(d)
    }
  end

  #
  # List of supported commands.
  #
  def commands
    {
    }
  end

  #
  # Name for this dispatcher
  #
  def name
    "Standard extension"
  end

end
