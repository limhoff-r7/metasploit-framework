require 'spec_helper'

describe Metasploit::Framework::Attempt::Creation::Single do
  include_context 'Metasploit::Framework::Attempt::Creation::Base'

  #
  # Shared examples
  #

  shared_examples_for 'delegates to #exploit_instance' do |method|
    context "##{method}" do
      subject(method) do
        creation.send(method)
      end

      context 'with #exploit_instance' do
        #
        # lets
        #

        let(:expected) do
          double(method)
        end

        #
        # Callbacks
        #

        before(:each) do
          expect(exploit_instance).to receive(method).and_return(expected)
        end

        it "is #exploit_instance's ##{method}" do
          expect(send(method)).to eq(expected)
        end
      end

      context 'without #exploit_instance' do
        let(:exploit_instance) do
          nil
        end

        it { should be_nil }
      end
    end
  end

  subject(:creation) do
    described_class.new(
        attempted_at: attempted_at,
        cache_exploit_class: cache_exploit_class,
        exploit_instance: exploit_instance,
        exploited: exploited,
        vuln: vuln
    )
  end

  let(:vuln) do
    FactoryGirl.build(
        :mdm_vuln
    )
  end

  context 'CONSTANTS' do
    context 'ATTEMPT_TYPES' do
      subject(:attempt_types) do
        described_class::ATTEMPT_TYPES
      end

      it { should include :exploit }
      it { should include :vuln }
    end
  end

  context 'validations' do
    let(:attempt_type) do
      [:exploit, :vuln].sample
    end

    #
    # Callbacks
    #

    before(:each) do
      allow(creation).to receive(:attempt_type).and_return(attempt_type)
    end

    context 'attempt_type errors' do
      subject(:attempt_type_errors) do
        creation.errors[:attempt_type]
      end

      #
      # lets
      #

      let(:error) do
        I18n.translate!('errors.messages.inclusion')
      end

      #
      # Callbacks
      #

      before(:each) do
        creation.valid?
      end

      context 'with :exploit' do
        let(:attempt_type) do
          :exploit
        end

        it { should_not include(error) }
      end

      context 'with :vuln' do
        let(:attempt_type) do
          :vuln
        end

        it { should_not include(error) }
      end

      context 'with nil' do
        let(:attempt_type) do
          nil
        end

        it { should include(error) }
      end
    end

    context 'username errors' do
      subject(:username_errors) do
        creation.errors[:username]
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
        allow(creation).to receive(:username).and_return(username)
        creation.valid?
      end

      context 'with #username' do
        let(:username) do
          'user.name'
        end

        it { should_not include(error) }
      end

      context 'without #username' do
        let(:username) do
          nil
        end

        it { should include(error) }
      end
    end

    it { should validate_presence_of :vuln }
  end

  context '#attempt_type' do
    subject(:attempt_type) do
      creation.send(:attempt_type)
    end

    it 'delegates to class method' do
      expected = double('::attempt_type')

      expect(creation.class).to receive(:attempt_type).and_return(expected)
      expect(attempt_type).to eq(expected)
    end
  end

  context '#attributes' do
    subject(:attributes) do
      creation.send(:attributes)
    end

    it_should_behave_like 'Metasploit::Framework::Attempt::Creation::Single#attributes'
  end

  it_should_behave_like 'delegates to #exploit_instance', :fail_detail
  it_should_behave_like 'delegates to #exploit_instance', :fail_reason

  context '#username' do
    subject(:username) do
      creation.username
    end

    context 'with #exploit_instance' do
      it "is #exploit_instance's #owner" do
        expect(exploit_instance.owner).not_to be_nil
        expect(username).to eq(exploit_instance.owner)
      end
    end

    context 'without #exploit_instance' do
      let(:exploit_instance) do
        nil
      end

      it { should be_nil }
    end
  end
end