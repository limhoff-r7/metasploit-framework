shared_examples_for 'Metasploit::Framework::UI::Console::Command::Parent' do
  it_should_behave_like 'Metasploit::Framework::UI::Command::Parent'

  context '#blank_tab_completions' do
    subject(:blank_tab_completions) do
      command.send(:blank_tab_completions)
    end

    shared_context 'subcommand blank_tab_completions' do
      #
      # lets
      #

      let(:subcommand) do
        double('Metasploit::Framework::UI::Console::Command::Child')
      end

      let(:subcommand_blank_tab_completions) do
        [
            'subcommand',
            'tab',
            'completions'
        ]
      end

      #
      # Callbacks
      #

      before(:each) do
        subcommand.should_receive(:blank_tab_completions).and_return(subcommand_blank_tab_completions)
        command.should_receive(:subcommand).and_return(subcommand)
      end

      it 'should include subcommand blank_tab_completions' do
        subcommand_blank_tab_completions.each do |completion|
          blank_tab_completions.should include completion
        end
      end
    end

    context 'with words' do
      let(:words) do
        Array.new(2) { |i|
          "word#{i}"
        }
      end

      it_should_behave_like 'subcommand blank_tab_completions'
    end

    context 'without words' do
      it { should include '-h' }
      it { should include '--help' }

      it_should_behave_like 'subcommand blank_tab_completions'
    end
  end

  context '#partial_tab_completions' do
    subject(:partial_tab_completions) do
      command.partial_tab_completions
    end

    it 'should delegate to #subcommand' do
      expected = double('#partial_tab_completions')

      command.send(:subcommand).should_receive(:partial_tab_completions).and_return(expected)
      partial_tab_completions.should == expected
    end
  end
end