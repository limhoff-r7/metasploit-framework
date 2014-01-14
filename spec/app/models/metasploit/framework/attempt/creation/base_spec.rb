require 'spec_helper'

describe Metasploit::Framework::Attempt::Creation::Base do
  include_context 'Metasploit::Framework::Attempt::Creation::Base'

  subject(:creation) do
    described_class.new(
        attempted_at: attempted_at,
        cache_exploit_class: cache_exploit_class,
        exploit_instance: exploit_instance,
        exploited: exploited
    )
  end

  it { should be_a Metasploit::Framework::Creation }

  context 'validations' do
    it { should validate_presence_of :exploit_instance }
    it { should ensure_inclusion_of(:exploited).in_array([false, true]) }
  end

  context '#attempted_at' do
    subject(:actual_attempted_at) do
      creation.attempted_at
    end

    it 'uses attribute :attempted_at' do
      expect(actual_attempted_at).to eq(attempted_at)
    end

    context 'default' do
      let(:expected_attempted_at) do
        nil
      end

      it { should be_a Time }
    end
  end

  context '#cache_exploit_class' do
    subject(:actual_cache_exploit_class) do
      creation.cache_exploit_class
    end

    it 'uses attribute :cache_exploit_class' do
      expect(actual_cache_exploit_class).to eq(cache_exploit_class)
    end

    context 'default' do
      let(:cache_exploit_class) do
        nil
      end

      it "uses #exploit_instance's Object#class's Metasploit::Framework::Module::Class::MetasploitClass#module_class" do
        expect(actual_cache_exploit_class).to eq(exploit_instance.class.module_class)
      end
    end
  end

  context '#exploited?' do
    subject(:exploited?) do
      creation.exploited?
    end

    context 'default' do
      let(:exploited) do
        nil
      end

      it { should be_false }
    end
  end
end