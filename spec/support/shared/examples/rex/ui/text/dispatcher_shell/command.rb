# A command defined inside a {Rex::Ui::Text::DispatcherShell::CommandDispatcher}.
shared_examples_for 'Rex::Ui::Text::DispatcherShell command' do |name, options={}|
  options.assert_valid_keys(:help, :tab_completion)

  help = options.fetch(:help)
  tab_completion = options.fetch(:tab_completion)

  define_singleton_method(:it_is_expected_to_respond_to_cmd_helper) do |suffix, expected|
    expectation = :not_to

    if expected
      expectation = :to
    end

    it { is_expected.send(expectation, respond_to("cmd_#{name}_#{suffix}")) }
  end

  it { is_expected.to respond_to "cmd_#{name}" }

  it_is_expected_to_respond_to_cmd_helper(:help, help)
  it_is_expected_to_respond_to_cmd_helper(:tabs, tab_completion)
end