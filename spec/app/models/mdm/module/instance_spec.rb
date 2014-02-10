require 'spec_helper'

describe Mdm::Module::Instance do
  include_context 'Msf::Simple::Framework'

  subject(:module_instance) do
    FactoryGirl.build(:mdm_module_instance)
  end

  context 'factories' do
    context 'mdm_module_instance' do
      subject(:mdm_module_instance) do
        FactoryGirl.build(
            :mdm_module_instance,
            module_class: module_class
        )
      end

      context '#module_class' do
        let(:module_class) do
          FactoryGirl.create(
              :mdm_module_class,
              module_type: module_type
          )
        end

        context 'with Mdm::Module::Class#module_type' do
          include_context 'Metasploit::Framework::Spec::Constants cleaner'

          #
          # lets
          #

          let(:metasploit_instance) do
            framework.modules.create_from_module_class(module_class)
          end

          #
          # Callbacks
          #

          before(:each) do
            mdm_module_instance.save!
          end

          context 'auxiliary' do
            let(:module_type) do
              'auxiliary'
            end

            it 'can be created' do
              expect(metasploit_instance).not_to be_nil
            end
          end

          context 'encoders' do
            let(:module_type) do
              'encoder'
            end

            it 'can be created' do
              expect(metasploit_instance).not_to be_nil
            end
          end

          context 'exploits' do
            let(:module_type) do
              'exploit'
            end

            it 'can be created' do
              expect(metasploit_instance).not_to be_nil
            end
          end

          context 'nops' do
            let(:module_type) do
              'nop'
            end

            it 'can be created' do
              expect(metasploit_instance).not_to be_nil
            end
          end

          context 'payloads' do
            let(:module_type) do
              'payload'
            end

            context 'with Mdm::Module::Class#payload_type' do
              let(:module_class) do
                FactoryGirl.create(
                    :mdm_module_class,
                    module_type: module_type,
                    payload_type: payload_type
                )
              end

              context 'single' do
                let(:payload_type) do
                  'single'
                end

                it 'can be created' do
                  expect(metasploit_instance).not_to be_nil
                end
              end

              context 'staged' do
                let(:payload_type) do
                  'staged'
                end

                it 'can be created' do
                  expect(metasploit_instance).not_to be_nil
                end
              end
            end
          end

          context 'post' do
            let(:module_type) do
              'post'
            end

            it 'can be created' do
              expect(metasploit_instance).not_to be_nil
            end
          end
        end
      end
    end
  end
end