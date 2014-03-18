# -*- coding: binary -*-

###
#
# Extended API user interface.
#
###
class Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher::Extapi

  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/extapi/window'
  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/extapi/service'
  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/extapi/clipboard'
  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/extapi/adsi'

  Klass = Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher::Extapi

  Dispatchers =
    [
      Klass::Window,
      Klass::Service,
      Klass::Clipboard,
      Klass::Adsi
    ]

  include Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher

  #
  # Initializes an instance of the extended API command interaction.
  #
  def initialize(shell)
    super

    Dispatchers.each { |d| shell.enstack_dispatcher(d) }
  end

  #
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
    "Extended API Extension"
  end

end
