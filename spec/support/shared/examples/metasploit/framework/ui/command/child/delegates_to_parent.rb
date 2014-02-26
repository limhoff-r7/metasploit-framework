shared_examples_for 'Metasploit::Framework::UI::Command::Child delegates to #parent' do |method|
  context "##{method}" do
    # no let name so that it doesn't interfere with outer lets
    subject do
      command.send(method)
    end

    context 'with #parent' do
      it "uses ##{method} on #parent" do
        expected = double(method)
        expect(parent).to receive(method).and_return(expected)

        expect(subject).to eq(expected)
      end
    end

    context 'without #parent' do
      let(:parent) do
        nil
      end

      it 'does not raise error' do
        expect {
          subject
        }.not_to raise_error
      end
    end
  end
end