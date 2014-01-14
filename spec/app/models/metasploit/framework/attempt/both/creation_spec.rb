require 'spec_helper'

require 'file/find'

describe Metasploit::Framework::Attempt::Both::Creation do
  include_context 'Metasploit::Framework::Attempt::Creation::Base'

  subject(:creation) do
    described_class.new(
        attempted_at: attempted_at,
        cache_exploit_class: cache_exploit_class,
        exploit_instance: exploit_instance,
        exploited: exploited,
        host: host,
        service: service
    )
  end

  #
  # lets
  #

  let(:host) do
    FactoryGirl.build(:mdm_host)
  end

  let(:service) do
    FactoryGirl.build(
        :mdm_service,
        host: host
    )
  end


  it { should be_a Metasploit::Framework::Attempt::Creation::Base }

  context '#create' do
    #
    # Shared examples
    #

    shared_examples_for 'passes attempt attributes' do
      it 'passes #attempted_at as :attempted_at' do
        expect(attempt_creation_class).to receive(:new).with(
                                     hash_including(
                                         attempted_at: creation.attempted_at
                                     )
                                 ).and_call_original

        create
      end

      it 'passes #cache_exploit_class as :cache_exploit_class' do
        expect(attempt_creation_class).to receive(:new).with(
                                              hash_including(
                                                  cache_exploit_class: cache_exploit_class
                                              )
                                          ).and_call_original

        create
      end

      it 'passes #exploit_instance as :exploit_instance' do
        expect(attempt_creation_class).to receive(:new).with(
                                     hash_including(
                                         exploit_instance: exploit_instance
                                     )
                                 ).and_call_original

        create
      end

      it 'passes #exploited? as :exploited' do
        expect(attempt_creation_class).to receive(:new).with(
                                     hash_including(
                                         exploited: exploited
                                     )
                                 ).and_call_original

        create
      end

      it 'passes #vuln as :vuln' do
        expect(attempt_creation_class).to receive(:new).with(
                                     hash_including(
                                         vuln: creation.vuln
                                     )
                                 ).and_call_original

        create
      end
    end

    subject(:create) do
      creation.create
    end

    it 'creates an Mdm::ExploitAttempt' do
      expect {
        create
      }.to change(Mdm::ExploitAttempt, :count).by(1)
    end

    it 'creates an Mdm::VulnAttempt' do
      expect {
        create
      }.to change(Mdm::VulnAttempt, :count).by(1)
    end

    context 'with pre-existing Mdm::Vuln' do
      #
      # lets
      #

      let(:vuln) do
        FactoryGirl.create(
            :mdm_vuln,
            host: host,
            service: service
        )
      end

      #
      # Callbacks
      #

      before(:each) do
        allow(creation).to receive(:vuln).and_return(vuln)
      end

      it 'does not create an Mdm::Vuln' do
        expect {
          create
        }.to change(Mdm::Vuln, :count).by(0)
      end
    end

    context 'without pre-existing Mdm::Vuln' do
      it 'creates an Mdm::Vuln' do
        expect {
          create
        }.to change(Mdm::Vuln, :count).by(1)
      end
    end

    context 'Metasploit::Framework::Attempt::Exploit::Creation' do
      let(:attempt_creation_class) do
        Metasploit::Framework::Attempt::Exploit::Creation
      end

      it_should_behave_like 'passes attempt attributes'

      it 'passes #host as :host' do
        expect(attempt_creation_class).to receive(:new).with(
                                              hash_including(
                                                  host: host
                                              )
                                          ).and_call_original

        create
      end

      it 'passes #service as :service' do
        expect(attempt_creation_class).to receive(:new).with(
                                              hash_including(
                                                  service: service
                                              )
                                          ).and_call_original

        create
      end
    end

    context 'Metasploit::Framework::Attempt::Vuln::Creation' do
      let(:attempt_creation_class) do
        Metasploit::Framework::Attempt::Vuln::Creation
      end

      it_should_behave_like 'passes attempt attributes'
    end
  end

  context '#vuln' do
    subject(:vuln) do
      creation.vuln
    end

    it 'is memoized' do
      expected = double('#vuln')
      creation.instance_variable_set :@vuln, expected

      expect(vuln).to eq(expected)
    end

    it { should be_a Mdm::Vuln }
    it { should be_persisted }

    context 'Metasploit::Framework::Vuln::Synchronization' do
      it 'passes #host as :host' do
        expect(Metasploit::Framework::Vuln::Synchronization).to receive(:new).with(
                                                                    hash_including(
                                                                        host: host
                                                                    )
                                                                ).and_call_original

        vuln
      end

      it "passes #cache_exploit_class's  Mdm::Module::Class#module_instance as :source" do
        expect(Metasploit::Framework::Vuln::Synchronization).to receive(:new).with(
                                                                    hash_including(
                                                                        source: cache_exploit_class.module_instance
                                                                    )
                                                                ).and_call_original

        vuln
      end

      it 'passes #service as :service' do
        expect(Metasploit::Framework::Vuln::Synchronization).to receive(:new).with(
                                                                    hash_including(
                                                                        service: service
                                                                    )
                                                                ).and_call_original

        vuln
      end
    end
  end
end