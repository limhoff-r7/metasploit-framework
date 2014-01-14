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
            'stages/windows/meterpreter/reverse_tcp',
            'stages/java/meterpreter/reverse_tcp',
            'stages/php/meterpreter/reverse_tcp',
            'singles/php/meterpreter_reverse_tcp/reverse_tcp',
            'singles/ruby/shell_reverse_tcp/reverse_tcp',
            'singles/cmd/unix/interact/find_shell',
            'singles/cmd/unix/reverse/reverse_tcp_double',
            'singles/cmd/unix/reverse_perl/reverse_tcp',
            'singles/cmd/unix/reverse_netcat_gaping/reverse_tcp',
            'stages/windows/meterpreter/reverse_nonx_tcp',
            'stages/windows/meterpreter/reverse_ord_tcp',
            'stages/windows/shell/reverse_tcp',
            'singles/generic/shell_reverse_tcp/reverse_tcp'
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

    let(:compatible_instances) do
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
      allow(payload_compatibility).to receive(:compatible_instances).and_return(compatible_instances)
    end

    it 'is reference_names from #compatible_instances' do
      expect(compatible_class_reference_names).to match_array(reference_names)
    end
  end

  context '#compatible_instances' do
    subject(:compatible_instances) do
      payload_compatibility.compatible_instances
    end

    context 'with Mdm::Module::Instances' do

    end

    context 'without Mdm::Module::Instances' do

    end
  end
end