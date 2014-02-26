shared_examples_for 'validates Metasploit::Framework::UI::Console::Command#dispatcher is fanged' do
  subject(:dispatcher_errors) do
    command.errors[:dispatcher]
  end

  #
  # lets
  #

  let(:error) do
    I18n.translate!('errors.messages.defanged')
  end

  #
  # Callbacks
  #

  before(:each) do
    msf_ui_console_driver.instance_variable_set :@defanged, defanged

    command.valid?
  end

  context 'with defanged' do
    let(:defanged) do
      true
    end

    it 'adds error on :dispatcher' do
      expect(dispatcher_errors).to include(error)
    end
  end

  context 'without defanged' do
    let(:defanged) do
      false
    end

    it 'does not add error on :dispatcher' do
      expect(dispatcher_errors).not_to include(error)
    end
  end
end