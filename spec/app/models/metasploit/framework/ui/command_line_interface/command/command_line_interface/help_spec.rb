require 'spec_helper'

describe Metasploit::Framework::UI::CommandLineInterface::Command::CommandLineInterface::Help do
  subject(:command) do
    described_class.new(
        parent: parent
    )
  end

  let(:parent) do
    Metasploit::Framework::UI::CommandLineInterface::Command::CommandLineInterface.new
  end

  it_should_behave_like 'Metasploit::Framework::UI::Command::Child'

  context '#examples' do
    include_context 'output'

    subject(:examples) do
      command.send(:examples)
    end

    it "uses msfcli in examples" do
      expect(output).to match /^msfcli/
    end
  end

  context '#run_with_valid' do
    include_context 'output'

    subject(:run_with_valid) do
      command.send(:run_with_valid)
    end

    it 'prints usage' do
      expect(command).to receive(:usage)

      quietly
    end

    it 'prints examples' do
      expect(command).to receive(:examples)

      quietly
    end
  end
end