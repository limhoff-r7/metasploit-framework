# -*- coding: binary -*-

###
#
# The password database portion of the privilege escalation extension.
#
###
class Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher::Priv::Passwd
  include Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher

  Klass = Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher::Priv::Passwd

  #
  # List of supported commands.
  #
  def commands
    {
      "hashdump" => "Dumps the contents of the SAM database"
    }
  end

  #
  # Name for this dispatcher.
  #
  def name
    "Priv: Password database"
  end

  #
  # Displays the contents of the SAM database
  #
  def cmd_hashdump(*args)
    client.priv.sam_hashes.each { |user|
      print_line("#{user}")
    }

    return true
  end

end
