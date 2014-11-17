# A command defined inside a {Rex::Ui::Text::DispatcherShell::CommandDispatcher}.
shared_examples_for 'Rex::Ui::Text::DispatcherShell command' do |name, options={}|
  options.assert_valid_keys(:tab_completion)

  tab_completion = options.fetch(:tab_completion)

  it { is_expected.to respond_to "cmd_#{name}" }
  it { is_expected.to respond_to "cmd_#{name}_help" }

  expect_respond_to = :not_to

  if tab_completion
    expect_respond_to = :to
  end

  it { is_expected.send(expect_respond_to, respond_to("cmd_#{name}_tabs")) }
end