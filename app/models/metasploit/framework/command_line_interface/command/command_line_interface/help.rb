class Metasploit::Framework::CommandLineInterface::Command::CommandLineInterface::Help < Metasploit::Framework::CommandLineInterface::Command::Base
  include Metasploit::Framework::Command::Child

  protected

  def run_with_valid
    usage
    print_line
    examples
  end

  private

  def examples
    print_line 'Examples:'
    print_line
    print_line "msfcli multi/handler payload=windows/meterpreter/reverse_tcp lhost=IP E"
    print_line "msfcli auxiliary/scanner/http/http_version rhosts=IP encoder= post= nop= E"
  end

  def usage
    table = Rex::Ui::Text::Table.new(
        'Header'  => "Usage: #{$0} (<auxiliary_full_name>|<auxiliary_reference_name>|<exploit_full_name>|<exploit_reference_name>) [<option=value>]* [MODE]",
        'Indent'  => 4,
        'Columns' => ['Mode', 'Description']
    )

    table << ['(H)elp',        "You're looking at it baby!"]
    table << ['(S)ummary',     'Show information about this module']
    table << ['(O)ptions',     'Show available options for this module']
    table << ['(A)dvanced',    'Show available advanced options for this module']
    table << ['(I)DS Evasion', 'Show available ids evasion options for this module']
    table << ['(P)ayloads',    'Show available payloads for this module']
    table << ['(T)argets',     'Show available targets for this exploit module']
    table << ['(AC)tions',     'Show available actions for this auxiliary module']
    table << ['(C)heck',       'Run the check routine of the selected module']
    table << ['(E)xecute',     'Execute the selected module']

    print table.to_s
  end
end