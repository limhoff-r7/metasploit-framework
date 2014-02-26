# Checks if a remote host(s) is vulnerable to an exploit
class Metasploit::Framework::UI::Console::Command::Check < Metasploit::Framework::UI::Console::Command::Base
  include Metasploit::Framework::UI::Console::Command::Parent

  self.description = 'Check to see if a target is vulnerable'

  #
  # Subcommands
  #

  subcommand :help
  subcommand :simple,
             default: true
end