shared_examples_for 'Metasploit::Framework::UI::Command::Child' do
  context 'validations' do
    it { should validate_presence_of :parent }
  end

  it_should_behave_like 'Metasploit::Framework::UI::Command::Child delegates to #parent', :words

  it { should_not respond_to(:words=) }
end