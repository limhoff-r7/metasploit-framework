require 'spec_helper'

describe Metasploit::Framework::Module::Target::Compatibility::Payload do
  subject(:payload_compatibility) do
    described_class.new
  end

  context 'CONSTANTS' do
    context 'DEFAULT_REFERENCE_NAMES' do
      subject(:default_reference_names) do
        described_class::DEFAULT_REFERENCE_NAMES
      end

      it {
        should == [
            'windows/meterpreter/reverse_tcp',
            'java/meterpreter/reverse_tcp',
            'php/meterpreter/reverse_tcp',
            'php/meterpreter_reverse_tcp',
            'ruby/shell_reverse_tcp',
            'cmd/unix/interact',
            'cmd/unix/reverse',
            'cmd/unix/reverse_perl',
            'cmd/unix/reverse_netcat_gaping',
            'windows/meterpreter/reverse_nonx_tcp',
            'windows/meterpreter/reverse_ord_tcp',
            'windows/shell/reverse_tcp',
            'generic/shell_reverse_tcp'
        ]
      }

      it { should be_frozen }
    end
  end

  context 'validations' do
    it { should validate_presence_of :target_model }
  end

  context '#compatible_class_reference_names' do
    subject(:compatible_class_reference_names) do
      payload_compatibility.compatible_class_reference_names
    end

    #
    # lets
    #

    let(:each_compatible_instance) do
      reference_names.collect { |reference_name|
        double('compatible instance', reference_name: reference_name)
      }
    end

    let(:reference_names) do
      Array.new(2) { |i|
        "reference/name/#{i}"
      }
    end

    #
    # Callbacks
    #

    before(:each) do
      allow(payload_compatibility).to receive(:each_compatible_instance).and_return(each_compatible_instance)
    end

    it 'is reference_names from #each_compatible_instance' do
      expect(compatible_class_reference_names).to match_array(reference_names)
    end
  end
end