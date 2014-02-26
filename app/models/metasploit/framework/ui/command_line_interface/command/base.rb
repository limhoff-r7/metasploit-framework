class Metasploit::Framework::UI::CommandLineInterface::Command::Base < Metasploit::Framework::UI::Command::Base
  private

  def output
    @output ||= Rex::Ui::Text::Output::Stdio.new
  end
end