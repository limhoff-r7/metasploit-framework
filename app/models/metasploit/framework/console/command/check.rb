# Checks if a remote host(s) is vulnerable to an exploit
class Metasploit::Framework::Console::Command::Check < Metasploit::Framework::Console::Command::Base
  include Metasploit::Framework::Console::Command::Parent

  self.description = 'Check to see if a target is vulnerable'

  #
  # Subcommands
  #

  subcommand :help
  subcommand :simple,
             default: true
end