shared_examples_for 'Msf::Module::Target::SaveRegisters' do
  #
  # lets
  #

  let(:metasploit_instance) do
    double('#metasploit_instance', reference_name: 'reference/name')
  end

  #
  # Callbacks
  #

  before(:each) do
    target.metasploit_instance = metasploit_instance
  end

  context '#declared_save_registers' do
    subject(:declared_save_registers) do
      target.declared_save_registers
    end

    before(:each) do
      target.opts['SaveRegisters'] = save_registers
    end

    context "with ''" do
      let(:save_registers) do
        ''
      end

      it 'logs warning' do
        expect(target).to receive(:wlog)

        declared_save_registers
      end

      it { should be_nil }
    end

    context 'with []' do
      let(:save_registers) do
        []
      end

      it 'logs warning' do
        expect(target).to receive(:wlog)

        declared_save_registers
      end

      it { should be_nil }
    end

    context 'with nil' do
      let(:save_registers) do
        nil
      end

      it 'does not log warning' do
        expect(target).not_to receive(:wlog)

        declared_save_registers
      end

      it { should be_nil }
    end

    context 'with String' do
      let(:save_registers) do
        'eax'
      end

      it 'converts to Array<(String>)>' do
        expect(declared_save_registers).to eq([save_registers])
      end
    end

    context 'with Array<String>' do
      let(:save_registers) do
        [
            'eax',
            'ecx'
        ]
      end

      it 'returns registers as in #opts' do
        expect(declared_save_registers).to eq(save_registers)
      end
    end
  end

  context '#save_registers' do
    subject(:save_registers) do
      target.save_registers
    end

    before(:each) do
      allow(target).to receive(:declared_save_registers).and_return(declared_save_registers)
    end

    context 'with declared_save_registers' do
      let(:declared_save_registers) do
        [
            'eax'
        ]
      end

      it 'is #declared_save_registers' do
        expect(save_registers).to eq(declared_save_registers)
      end
    end

    context 'without declared_save_registers' do
      let(:declared_save_registers) do
        nil
      end

      it 'uses save_registers from #metasploit_instance' do
        expected = double('metapsloit_instance.save_registers')
        expect(metasploit_instance).to receive(:save_registers).and_return(expected)
        expect(save_registers).to eq(expected)
      end
    end
  end
end