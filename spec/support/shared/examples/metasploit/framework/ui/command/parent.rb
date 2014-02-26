shared_examples_for 'Metasploit::Framework::UI::Command::Parent' do
  context 'validations' do
    it { should ensure_inclusion_of(:subcommand_name).in_array(described_class.subcommand_names) }
  end

  context '#run_with_valid' do
    subject(:run_with_valid) do
      command.send(:run_with_valid)
    end

    it 'should run #subcommand' do
      command.send(:subcommand).should_receive(:run)

      run_with_valid
    end
  end

  context '#subcommand' do
    subject(:subcommand) do
      command.send(:subcommand)
    end

    it 'should look up #subcommand_name in #subcommand_by_name' do
      subcommand_by_name = command.send(:subcommand_by_name)
      subcommand_name = command.send(:subcommand_name)
      expected_subcommand = double('#subcommand')
      subcommand_by_name[subcommand_name] = expected_subcommand

      subcommand.should == expected_subcommand
    end
  end

  context '#subcommand_by_name' do
    subject(:subcommand_by_name) do
      command.send(:subcommand_by_name)
    end

    it { should be_a Hash }

    context 'with unknown name' do
      subject(:subcommand) do
        subcommand_by_name[name]
      end

      let(:name) do
        'unknown_subcommand'
      end

      it { should be_nil }
    end

    context 'with known name' do
      subject(:subcommand) do
        subcommand_by_name[name]
      end

      let(:name) do
        described_class.subcommand_class_by_name.keys.sample
      end

      it { should be_a Metasploit::Framework::UI::Command::Child }

      context 'parent' do
        subject(:parent) do
          subcommand.parent
        end

        it 'should be this parent command' do
          parent.should == command
        end
      end
    end
  end

  context '#subcommand_name' do
    subject(:subcommand_name) do
      command.subcommand_name
    end

    context 'default' do
      it 'should be default_subcommand_name of class' do
        subcommand_name.should == described_class.default_subcommand_name
      end
    end

    context 'with value' do
      let(:expected_subcommand_name) do
        double('#subcommand_name')
      end

      before(:each) do
        command.subcommand_name = expected_subcommand_name
      end

      it 'should return set value' do
        command.subcommand_name.should == expected_subcommand_name
      end
    end

    context 'without value' do
      it 'should #parse_words before calling default_subcommand_name so words can override default' do
        command.should_receive(:parse_words).ordered
        described_class.should_receive(:default_subcommand_name).ordered

        subcommand_name
      end
    end
  end
end