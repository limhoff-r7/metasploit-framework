shared_examples_for 'Msf::Logging' do
  after(:each) do
    Msf::Logging.teardown
  end
end