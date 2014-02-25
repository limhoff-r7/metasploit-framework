shared_examples_for 'Metasploit::Framework::Console::Command::Child' do
  context 'validations' do
    it { should validate_presence_of :parent }
  end

  it_should_behave_like 'Metasploit::Framework::Console::Command::Child delegates to #parent', :dispatcher
  it_should_behave_like 'Metasploit::Framework::Console::Command::Child delegates to #parent', :option_parser
  it_should_behave_like 'Metasploit::Framework::Console::Command::Child delegates to #parent', :partial_word
  it_should_behave_like 'Metasploit::Framework::Console::Command::Child delegates to #parent', :words

  it { should_not respond_to(:partial_word=) }
  it { should_not respond_to(:words=) }
end