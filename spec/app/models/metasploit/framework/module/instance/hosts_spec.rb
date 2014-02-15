require 'spec_helper'

describe Metasploit::Framework::Module::Instance::Hosts do
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Simple::Framework'

  subject(:hosts) do
    described_class.new(
        metasploit_instance: metasploit_instance
    )
  end

  let(:cache_exploit_class) do
    FactoryGirl.create(
        :mdm_module_class,
        module_type: 'exploit'
    )
  end

  let(:cache_exploit_instance) do
    FactoryGirl.create(
        :mdm_module_instance,
        module_class: cache_exploit_class
    )
  end

  let(:metasploit_instance) do
    framework.modules.create_from_module_class(cache_exploit_instance.module_class)
  end

  context 'CONSTANTS' do
    context 'DEFAULT_REMOTE' do
      subject(:default_remote) do
        described_class::DEFAULT_REMOTE
      end

      it { should == '50.50.50.50' }
    end
  end

  context '#default_local' do
    subject(:default_local) do
      hosts.default_local
    end

    it 'passes #remote to Rex::Socket.source_address' do
      expected = double('#remote')
      expect(hosts).to receive(:remote).and_return(expected)
      expect(Rex::Socket).to receive(:source_address).with(expected)

      default_local
    end
  end

  context '#local' do
    subject(:local) do
      hosts.local
    end

    before(:each) do
      metasploit_instance.datastore['LHOST'] = lhost
    end

    context 'with LHOST' do
      let(:lhost) do
        '192.168.0.1'
      end

      it 'uses LHOST' do
        expect(local).to eq(lhost)
      end
    end

    context 'without LHOST' do
      let(:lhost) do
        nil
      end

      it 'uses #default_local' do
        expected = double('#default_local')
        expect(hosts).to receive(:default_local).and_return(expected)
        expect(local).to eq(expected)
      end
    end
  end

  context '#remote' do
    subject(:remote) do
      hosts.remote
    end

    before(:each) do
      metasploit_instance.datastore['RHOST'] = rhost
    end

    context 'with RHOST' do
      let(:rhost) do
        '8.8.8.8'
      end

      it 'uses RHOST' do
        expect(remote).to eq(rhost)
      end
    end

    context 'without RHOST' do
      let(:rhost) do
        nil
      end

      it 'uses DEFAULT_REMOTE_HOST' do
        expect(remote).to eq(described_class::DEFAULT_REMOTE)
      end
    end
  end
end