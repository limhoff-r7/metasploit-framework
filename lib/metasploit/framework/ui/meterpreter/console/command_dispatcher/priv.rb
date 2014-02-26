# -*- coding: binary -*-

###
#
# Privilege escalation extension user interface.
#
###
class Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher::Priv
  include Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher

  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/priv/elevate'
  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/priv/passwd'
  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/priv/timestomp'

  Klass = Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher::Priv

  Dispatchers =
    [
      Klass::Elevate,
      Klass::Passwd,
      Klass::Timestomp,
    ]

  #
  # Initializes an instance of the priv command interaction.
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
    "Privilege Escalation"
  end

end
