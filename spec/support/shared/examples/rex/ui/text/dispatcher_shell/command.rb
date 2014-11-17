# A command defined inside a {Rex::Ui::Text::DispatcherShell::CommandDispatcher}.
shared_examples_for 'Rex::Ui::Text::DispatcherShell command' do |name|
  it { is_expected.to respond_to "cmd_#{name}" }
  it { is_expected.to respond_to "cmd_#{name}_help" }
  it { is_expected.to respond_to "cmd_#{name}_tabs" }
end