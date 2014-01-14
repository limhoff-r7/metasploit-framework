shared_examples_for 'validates presence of Metasploit::Framework::Command#metasploit_instance' do
  subject(:metasploit_instance_errors) do
    command.errors[:metasploit_instance]
  end

  #
  # lets
  #

  let(:error) do
    I18n.translate!('errors.messages.blank')
  end

  #
  # Callbacks
  #

  before(:each) do
    command.valid?
  end

  context 'with present' do
    include_context 'Msf::Ui::Console::Driver#metasploit_instance'

    it 'does not add error on :metasploit_instance' do
      expect(metasploit_instance_errors).not_to include(error)
    end
  end

  context 'without present' do
    let(:metasploit_instance) do
      nil
    end

    it 'adds error on :metasploit_instance' do
      expect(metasploit_instance_errors).to include(error)
    end
  end
end
