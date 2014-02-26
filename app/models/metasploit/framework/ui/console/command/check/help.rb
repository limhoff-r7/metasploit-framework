class Metasploit::Framework::UI::Console::Command::Check::Help < Metasploit::Framework::UI::Console::Command::Base
  include Metasploit::Framework::UI::Console::Command::Child

  protected

  def run_with_valid
    print option_parser.help
    print_line
    print_line "Check to see if target is vulnerable to #{dispatcher.metasploit_instance.full_name}"
  end
end