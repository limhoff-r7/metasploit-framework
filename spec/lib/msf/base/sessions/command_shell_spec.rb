require 'spec_helper'

describe Msf::Sessions::CommandShell do
  include_context 'Msf::Simple::Framework'

  subject(:command_shell) do
    described_class.new(
        rstream
    ).tap { |instance|
      instance.framework = framework
      instance.user_input = Rex::Ui::Text::Input::Stdio.new
      instance.user_output = Rex::Ui::Text::Output::Stdio.new
    }
  end

  let(:rstream) do
    double('RStream')
  end

  it_should_behave_like 'Msf::Session::Scriptable' do
    let(:base_class) do
      described_class
    end

    let(:base_instance) do
      command_shell
    end
  end
end