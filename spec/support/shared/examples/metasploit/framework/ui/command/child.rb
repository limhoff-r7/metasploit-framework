shared_examples_for 'Metasploit::Framework::Command::Child' do
  context 'validations' do
    it { should validate_presence_of :parent }
  end

  it_should_behave_like 'Metasploit::Framework::Command::Child delegates to #parent', :words

  it { should_not respond_to(:words=) }
end