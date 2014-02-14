shared_examples_for 'Msf::Module::SaveRegisters' do
  context '#save_registers' do
    subject(:save_registers) do
      metasploit_instance.save_registers
    end

    before(:each) do
      metasploit_instance.module_info = {
          'SaveRegisters' => module_info_save_registers
      }
    end

    context 'with nil' do
      let(:module_info_save_registers) do
        nil
      end

      it 'does not log warning' do
        expect(metasploit_instance).not_to receive(:wlog)

        save_registers
      end

      it { should be_nil }
    end

    context "with ''" do
      let(:module_info_save_registers) do
        ''
      end

      it 'logs warning' do
        expect(metasploit_instance).to receive(:wlog)

        save_registers
      end

      it { should be_nil }
    end

    context "with []" do
      let(:module_info_save_registers) do
        []
      end

      it 'logs warning' do
        expect(metasploit_instance).to receive(:wlog)

        save_registers
      end

      it { should be_nil }
    end

    context 'with String' do
      let(:module_info_save_registers) do
        'eax'
      end

      it 'converts it to Array<(String)>' do
        expect(save_registers).to eq([module_info_save_registers])
      end
    end

    context 'with Array<String>' do
      let(:module_info_save_registers) do
        [
            'eax',
            'ecx'
        ]
      end

      it 'does not change value' do
        expect(save_registers).to eq(module_info_save_registers)
      end
    end
  end
end