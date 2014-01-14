require 'spec_helper'

describe Metasploit::Framework::Attempt::Vuln::Creation do
  include_context 'Metasploit::Framework::Attempt::Creation::Base'

  subject(:creation) do
    described_class.new(
        attempted_at: attempted_at,
        cache_exploit_class: cache_exploit_class,
        exploit_instance: exploit_instance,
        exploited: exploited,
        vuln: vuln
    )
  end

  #
  # lets
  #

  let(:vuln) do
    FactoryGirl.build(
        :mdm_vuln
    )
  end

  context 'attempt_type' do
    subject(:attempt_type) do
      described_class.attempt_type
    end

    it { should == :vuln }
  end

  context '#attributes' do
    subject(:attributes) do
      creation.send(:attributes)
    end

    it_should_behave_like 'Metasploit::Framework::Attempt::Creation::Single#attributes'
  end

  context '#create' do
    subject(:create) do
      creation.create
    end

    it 'uses exploit_attempts association on #cache_exploit_class' do
      expect(cache_exploit_class).to receive(:vuln_attempts).and_call_original

      create
    end

    it 'uses #create! so validation errors are raised as exception and not missed in the framework.log' do
      expect(cache_exploit_class.vuln_attempts).to receive(:create!)

      create
    end

    it 'passes #attributes to #create!' do
      attributes = double('#attributes')
      expect(creation).to receive(:attributes).and_return(attributes)
      expect(cache_exploit_class.vuln_attempts).to receive(:create!).with(attributes)

      create
    end

    it 'creates an Mdm::VulnAttempt' do
      expect {
        create
      }.to change(Mdm::VulnAttempt, :count).by(1)
    end
  end
end