class Metasploit::Framework::CommandLineInterface::Command::Base < Metasploit::Framework::Command::Base
  private

  def output
    @output ||= Rex::Ui::Text::Output::Stdio.new
  end
end