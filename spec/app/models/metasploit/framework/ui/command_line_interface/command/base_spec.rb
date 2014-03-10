require 'spec_helper'

describe Metasploit::Framework::UI::CommandLineInterface::Command::Base, :ui do
  subject(:command) do
    described_class.new
  end

  context '#output' do
    subject(:output) do
      command.send(:output)
    end

    it { should be_a Rex::Ui::Text::Output::Stdio }

    it 'should be memoized' do
      expect(command.send(:output)).to equal(command.send(:output))
    end
  end
end