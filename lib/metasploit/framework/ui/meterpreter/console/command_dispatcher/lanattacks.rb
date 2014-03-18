# -*- coding: binary -*-
require 'rex/post/meterpreter'

###
#
# Lanattacks extension.
#
###
class Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher::Lanattacks

  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/lanattacks/dhcp'
  require 'metasploit/framework/ui/meterpreter/console/command_dispatcher/lanattacks/tftp'

  Klass = Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher::Lanattacks

  Dispatchers =
    [
      Klass::Dhcp,
      Klass::Tftp
    ]

  include Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher

  #
  # Initializes an instance of the lanattacks command interaction.
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
    "Lanattacks extension"
  end

end
