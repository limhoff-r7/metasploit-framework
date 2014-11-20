# @note Caller must define `#dispatcher_shell` which is expected to respond to `"cmd_#{name}"` and other methods.
#
# A command defined inside a {Rex::Ui::Text::DispatcherShell::CommandDispatcher}.
shared_examples_for 'Rex::Ui::Text::DispatcherShell command' do |name, options={}|
  options.assert_valid_keys(:help, :tab_completion)

  defines_help = options.fetch(:help)
  defines_tab_completion = options.fetch(:tab_completion)

  define_singleton_method(:it_defines_optional_cmd_feature) do |feature, expected, options={}|
    options.assert_valid_keys(:suffix)

    suffix = options.fetch(:suffix)

    description = "does not define"
    expectation = :not_to

    if expected
      description = "defines"
      expectation = :to
    end

    it "#{description} #{feature}" do
      expect(dispatcher_shell).send(expectation, respond_to("cmd_#{name}_#{suffix}"))
    end
  end

  context name do
    it 'is defined' do
      expect(dispatcher_shell).to respond_to "cmd_#{name}"
    end

    it_defines_optional_cmd_feature 'help',
                                    defines_help,
                                    suffix: :help

    it_defines_optional_cmd_feature 'tab completion',
                                    defines_tab_completion,
                                    suffix: :tabs
  end
end