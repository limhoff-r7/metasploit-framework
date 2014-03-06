require 'spec_helper'

describe Msf::Session::Scriptable do
  include_context 'Metasploit::Framework::Spec::Constants tracker'
  include_context 'Msf::Simple::Framework'

  let(:base_class) do
    described_class = self.described_class
    type = self.type

    Class.new do
      include Msf::Session
      include described_class
      include Rex::Ui::Subscriber

      define_singleton_method(:type) do
        type
      end
    end
  end

  let(:base_instance) do
    base_class.new.tap { |instance|
      instance.framework = framework
      instance.user_input = Rex::Ui::Text::Input::Stdio.new
      instance.user_output = Rex::Ui::Text::Output::Stdio.new
    }
  end

  let(:type) do
    types.sample
  end

  let(:types) do
    # must be a type that has a migrate.rb script for tests on the installed scripts path that uses migrate.rb as a
    # basename.
    ['meterpreter', 'shell']
  end

  it_should_behave_like 'Msf::Session::Scriptable'

  context '#execute_file' do
    subject(:execute_file) do
      base_instance.execute_file(path, args)
    end

    let(:args) do
      []
    end

    let(:path) do
      'path'
    end

    specify {
      expect {
        execute_file
      }.to raise_error(NotImplementedError)
    }
  end
end