class Metasploit::Framework::UI::Console::Command::Use::Help < Metasploit::Framework::UI::Console::Command::Base
  include Metasploit::Framework::UI::Console::Command::Child

  protected

  def run_with_valid
    print option_parser.help
    print_line
    print_line 'Used to interact with a module of a given full name (<module_type>/<reference_name>).'
  end
end
