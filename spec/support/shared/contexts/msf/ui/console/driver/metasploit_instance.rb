shared_context 'Msf::Ui::Console::Driver#metasploit_instance' do
  include_context 'database cleaner'
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Exploit metasploit_instance'

  #
  # Callbacks
  #

  before(:each) do
    msf_ui_console_driver.metasploit_instance = metasploit_instance
  end
end