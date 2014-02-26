shared_examples_for 'Metasploit::Framework::Console::Command::Child' do
  it_should_behave_like 'Metasploit::Framework::Command::Child'

  it_should_behave_like 'Metasploit::Framework::Command::Child delegates to #parent', :dispatcher
  it_should_behave_like 'Metasploit::Framework::Command::Child delegates to #parent', :option_parser
  it_should_behave_like 'Metasploit::Framework::Command::Child delegates to #parent', :partial_word

  it { should_not respond_to(:partial_word=) }
end