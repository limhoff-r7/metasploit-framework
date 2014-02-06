require 'spec_helper'

require 'msf/core/handler/bind_tcp'

describe Msf::Payload::Stager do
  subject(:stager) do
    stager_class.new
  end

  let(:module_info) do
    {
        'Arch' => ARCH_X86,
        'Stage' => {
            'Offsets' => stage_offset_relative_address_and_type_by_name
        }
    }
  end

  let(:stage_offset_relative_address_and_type_by_name) do
    {
        'STAGE' => [0xADD, 'TYPE']
    }
  end

  let(:stager_module) do
    described_class = self.described_class

    Module.new do
      extend  Metasploit::Framework::Module::Ancestor::Handler

      include described_class

      handler module_name: 'Msf::Handler::BindTcp'
    end
  end

  let(:stager_class) do
    module_info = self.module_info
    stage_offset_relative_address_and_type_by_name = self.stage_offset_relative_address_and_type_by_name
    stager_module = self.stager_module

    Class.new(Msf::Payload) do
      include stager_module

      define_method(:initialize) do |info={}|
        super(
            Msf::Module::ModuleInfo.merge!(
                info,
                module_info
            )
        )
      end
    end
  end

  context '#assemble_stage' do
    subject(:assemble_stage) do
      stager.send(:assemble_stage)
    end

    context 'with #stage_assembly' do
      let(:module_info) do
        super().tap { |module_info|
          module_info['Stage'] ||= {}
          module_info['Stage']['Assembly'] = stage_assembly
        }
      end

      let(:stage_assembly) do
        'stage_assembly'
      end

      it 'assembles the assembly' do
        assembled = double('#assemble')
        expect(stager).to receive(:assemble).with(stage_assembly, stage_offset_relative_address_and_type_by_name).and_return(assembled)
        expect(assemble_stage).to equal(assembled)
      end
    end

    context 'without #stage_assembly' do
      let(:module_info) do
        super().tap { |module_info|
          module_info['Stage'] ||= {}
          module_info['Stage']['Payload'] = stage_payload
        }
      end

      let(:stage_payload) do
        'stage_payload'
      end

      it { should be_a Metasploit::Framework::Payload::Assembled }

      context '#data' do
        subject(:data) do
          assemble_stage.data
        end

        it 'is #stage_payload' do
          expect(data).to equal(stage_payload)
        end
      end

      context '#offset_relative_address_and_type_by_name' do
        subject(:offset_relative_address_and_type_by_name) do
          assemble_stage.offset_relative_address_and_type_by_name
        end

        it 'is #stage_offset_relative_address_and_type_by_name' do
          expect(offset_relative_address_and_type_by_name).to equal(stage_offset_relative_address_and_type_by_name)
        end
      end
    end
  end

  context '#generate_stage' do
    subject(:generate_stage) do
      stager.generate_stage
    end

    #
    # lets
    #

    let(:assembled) do
      double(
          '#assemble',
          data: data,
          offset_relative_address_and_type_by_name: offset_relative_address_and_type_by_name
      )
    end

    let(:data) do
      'data'
    end

    let(:offset_relative_address_and_type_by_name) do
      {
          'NAME' => [0xADD, 'TYPE']
      }
    end

    #
    # Callbacks
    #

    before(:each) do
      allow(stager).to receive(:assemble_stage).and_return(assembled)
    end

    context '#substitute_vars' do
      it 'does substitutions on copy of assembled data' do
        expect(stager).to receive(:substitute_vars) do |generated, _|
          expect(generated).to eq(data)
          expect(generated).not_to equal(data)
        end

        generate_stage
      end

      it 'looks up substitutions with assembled offset_relative_address_and_type_by_name' do
        expect(stager).to receive(:substitute_vars) do |_, actual_offset_relative_address_and_type_by_name|
          expect(actual_offset_relative_address_and_type_by_name).to equal(offset_relative_address_and_type_by_name)
        end

        generate_stage
      end
    end
  end
end