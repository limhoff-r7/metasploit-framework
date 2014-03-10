require 'spec_helper'

describe Metasploit::Framework::UI::Command::Base, :ui do
  subject(:command) do
    described_class.new
  end

  context '#print_validation_errors' do
    include_context 'output'

    subject(:print_validation_errors) do
      command.send(:print_validation_errors)
    end

    it 'should use full messages' do
      command.errors.should_receive(:full_messages).and_return([])

      quietly
    end

    context 'with errors' do
      #
      # lets
      #

      let(:attribute) do
        :the_attribute
      end

      let(:error) do
        'is filled with errors'
      end

      #
      # Callbacks
      #

      before(:each) do
        command.errors[attribute] << error
      end

      it 'should print full messages as errors' do
        command.should_receive(:print_error).with("The attribute is filled with errors")

        print_validation_errors
      end
    end
  end

  context '#run' do
    subject(:run) do
      command.run
    end

    before(:each) do
      command.stub(valid?: valid)
    end

    context 'with valid' do
      let(:valid) do
        true
      end

      it 'should call #run_with_valid' do
        command.should_receive(:run_with_valid)

        run
      end
    end

    context 'without valid' do
      let(:valid) do
        false
      end

      it 'should call #print_validation_errors' do
        command.should_receive(:print_validation_errors)

        run
      end
    end
  end

  context '#words' do
    subject(:words) do
      command.words
    end

    it 'defaults to []' do
      expect(words).to eq([])
    end
  end
end