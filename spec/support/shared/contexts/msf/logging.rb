shared_examples_for 'Msf::Logging' do |options={}|
  options.assert_valid_keys(:after)

  scope = options.fetch(:after, :each)

  #
  # Callbacks
  #

  after(scope) do
    Msf::Logging.teardown
  end
end