require 'spec_helper'

describe Metasploit::Framework::Module::Instance::Failure::Creation do
  include_context 'Msf::Exploit metasploit_instance'

  subject(:creation) do
    described_class.new(
        exploit_instance: exploit_instance
    )
  end

  let(:exploit_instance) do
    metasploit_instance
  end

  context 'validations' do
    it { should validate_presence_of :exploit_instance }

    context 'host' do
      subject(:host_errors) do
        creation.errors[:host]
      end

      context 'with nil' do
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
          allow(creation).to receive(:host).and_return(nil)

          creation.valid?
        end

        it { should include(error) }
      end
    end
  end

  context '#create' do
    subject(:create) do
      creation.create
    end

    #
    # lets
    #

    let(:rhost) do
      FactoryGirl.generate :mdm_ipv4_address
    end

    let(:workspace) do
      FactoryGirl.create(:mdm_workspace)
    end

    #
    # let!s
    #

    let!(:host) do
      FactoryGirl.create(
          :mdm_host,
          address: rhost,
          workspace: workspace
      )
    end

    #
    # Callbacks
    #

    before(:each) do
      allow(exploit_instance).to receive(:workspace_record).and_return(workspace)
      exploit_instance.options['RHOST'] = true
      exploit_instance.datastore['RHOST'] = rhost
    end

    it 'passes #exploit_instance as :exploit_instance to Metasploit::Framework::Attempt::Both::Creation.new' do
      expect(Metasploit::Framework::Attempt::Both::Creation).to receive(:new).with(
                                                                    hash_including(
                                                                        exploit_instance: exploit_instance
                                                                    )
                                                                ).and_call_original

      create
    end

    it 'passes false as :exploited Metasploit::Framework::Attempt::Both::Creation.new' do
      expect(Metasploit::Framework::Attempt::Both::Creation).to receive(:new).with(
                                                                    hash_including(
                                                                        exploited: false
                                                                    )
                                                                ).and_call_original

      create
    end

    it 'passes #host as :host to Metasploit::Framework::Attempt::Both::Creation.new' do
      host = FactoryGirl.build(:mdm_host)
      allow(creation).to receive(:host).and_return(host)

      expect(Metasploit::Framework::Attempt::Both::Creation).to receive(:new).with(
                                                                    hash_including(
                                                                        host: host
                                                                    )
                                                                ).and_call_original

      create
    end

    it 'passes #service as :service to Metasploit::Framework::Attempt::Both::Creation.new' do
      service = FactoryGirl.create(:mdm_service, host: host)
      allow(creation).to receive(:service).and_return(service)

      expect(Metasploit::Framework::Attempt::Both::Creation).to receive(:new).with(
                                                                    hash_including(
                                                                        service: service
                                                                    )
                                                                ).and_call_original

      create
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
  end

  context '#host' do
    subject(:host) do
      creation.host
    end

    context 'with #exploit_instance' do
      before(:each) do
        exploit_instance.options['RHOST'] = rhost_option
      end

      context 'with RHOST option' do
        let(:rhost_option) do
          true
        end

        #
        # lets
        #

        let(:workspace) do
          FactoryGirl.create(:mdm_workspace)
        end

        #
        # Callbacks
        #

        before(:each) do
          allow(exploit_instance).to receive(:workspace_record).and_return(workspace)
          exploit_instance.datastore['RHOST'] = rhost
        end

        context 'with RHOST' do
          let(:rhost) do
            FactoryGirl.generate :mdm_ipv4_address
          end

          context 'with pre-existing Mdm::Host' do
            let!(:expected_host) do
              FactoryGirl.create(
                  :mdm_host,
                  address: rhost,
                  workspace: workspace
              )
            end

            it 'returns the pre-existing Mdm::Host' do
              expect(host).to eq(expected_host)
            end
          end

          context 'without pre-existing Mdm::Host' do
            it { should be_an Mdm::Host }
            it { should be_a_new_record }
          end
        end

        context 'without RHOST' do
          let(:rhost) do
            nil
          end

          it { should be_nil }
        end
      end

      context 'without RHOST option' do
        let(:rhost_option) do
          false
        end

        it { should be_nil }
      end
    end

    context 'without #exploit_instance' do
      let(:exploit_instance) do
        nil
      end

      it { should be_nil }
    end
  end

  context '#module_class' do
    subject(:module_class) do
      creation.module_class
    end

    it 'uses #module_class for exploit_instance.class' do
      expect(module_class).to eq(exploit_instance.class.module_class)
    end
  end
end