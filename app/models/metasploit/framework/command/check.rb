# Checks if a remote host(s) is vulnerable to an exploit
class Metasploit::Framework::Command::Check < Metasploit::Framework::Command::Base
  include Metasploit::Framework::Command::Parent

  self.description = 'Check to see if a target is vulnerable'

  #
  # Subcommands
  #

  subcommand :help
  subcommand :simple,
             default: true
end