require 'spec_helper'

describe Msf::Simple::Framework do
  context 'CONSTANTS' do
    context 'MODULE_SIMPLIFIER_BY_MODULE_TYPE' do
      subject(:module_simplifier_by_module_type) do
        described_class::MODULE_SIMPLIFIER_BY_MODULE_TYPE
      end

      its([Metasploit::Model::Module::Type::AUX]) { should == Msf::Simple::Auxiliary }
      its([Metasploit::Model::Module::Type::ENCODER]) { should == Msf::Simple::Encoder }
      its([Metasploit::Model::Module::Type::EXPLOIT]) { should == Msf::Simple::Exploit }
      its([Metasploit::Model::Module::Type::NOP]) { should == Msf::Simple::Nop }
      its([Metasploit::Model::Module::Type::PAYLOAD]) { should == Msf::Simple::Payload }
      its([Metasploit::Model::Module::Type::POST]) { should == Msf::Simple::Post }
    end
  end

  it_should_behave_like 'Msf::Simple::Framework::ModulePaths' do
    include_context 'Msf::Simple::Framework'

    subject do
      framework
    end
  end

  context 'create' do
    include_context 'Msf::Logging'

    context 'with options' do
      subject(:create) do
        described_class.create(options)
      end

      let(:options) do
        {}
      end

      context "['DisableDatabase']" do
        context 'with value' do
          let(:options) do
            {
                'DisableDatabase' => disable_database
            }
          end

          context 'with false' do
            let(:disable_database) do
              false
            end

            it 'should pass database_disabled: false to Msf::Framework.new' do
              framework = double("Msf::Framework").as_null_object
              Msf::Framework.should_receive(:new).with(
                  hash_including(
                      database_disabled: false
                  )
              ).and_call_original
              described_class.stub(:simplify)

              create
            end
          end

          context 'with nil' do
            let(:disable_database) do
              nil
            end

            it 'should pass database_disabled: false to Msf::Framework.new' do
              Msf::Framework.should_receive(:new).with(
                  hash_including(
                      database_disabled: false
                  )
              ).and_call_original
              described_class.stub(:simplify)

              create
            end
          end

          context 'with true' do
            let(:disable_database) do
              true
            end

            it 'should pass database_disabled: true to Msf::Framework.new' do
              Msf::Framework.should_receive(:new).with(
                  hash_including(
                      database_disabled: true
                  )
              ).and_call_original
              described_class.stub(:simplify)

              create
            end
          end
        end

        context 'without value' do
          it 'should pass database_disabled: false to Msf::Framework.new' do
            Msf::Framework.should_receive(:new).with(
                hash_including(
                    database_disabled: false
                )
            ).and_call_original
            described_class.stub(:simplify)

            create
          end
        end
      end

      context '[:module_types]' do
        let(:options) do
          {
              module_types: module_types
          }
        end

        context 'with valid module types' do
          include_context 'database cleaner'

          subject(:module_types) do
            # 1 .. length instead of 0 .. length since there needs to be at least one module_type
            number = rand(Metasploit::Model::Module::Type::ALL.length - 1) + 1
            # random module_types
            Metasploit::Model::Module::Type::ALL.sample(number)
          end

          it 'should simplify Msf::Framework using options containing only DeferModuleLoads, DisableLogging, and OnCreateProc' do
            described_class.should_receive(:simplify).with(
                an_instance_of(Msf::Framework),
                options.slice('DeferModuleLoads', 'DisableLogging', 'OnCreateProc')
            )

            create
          end
        end
      end
    end

    context 'without options' do
      include_context 'database cleaner'

      subject(:create) do
        described_class.create
      end

      after(:each) do
        # explicitly kill threads so that they don't exhaust connection pool
        thread_manager = create.threads
        threads = thread_manager.list

        threads.each do |thread|
          thread.kill
        end
      end

      it 'should be_a Msf::Framework' do
        create.should be_a  Msf::Framework
      end

      it 'should be_a Msf::Simple::Framework' do
        create.should be_a Msf::Simple::Framework
      end
    end
  end

  context 'load_config' do
    include_context 'Msf::Simple::Framework'

    subject(:load_config) do
      framework.load_config
    end

    #
    # lets
    #

    let(:key) do
      'KEY'
    end

    let(:value) do
      'value'
    end

    #
    # Callbacks
    #

    before(:each) do
      framework.pathnames.file.open('wb') { |f|
        f.puts "[framework/core]"
        f.puts "#{key}=#{value}"
      }
    end

    it "loads 'framework/core' group from framework.pathnames.file" do
      load_config

      expect(framework.data_store[key]).to eq(value)
    end
  end

  context 'save_config' do
    include_context 'Msf::Simple::Framework'

    subject(:save_config) do
      framework.save_config
    end

    #
    # lets
    #

    let(:key) do
      'KEY'
    end

    let(:value) do
      'value'
    end

    #
    # Callbacks
    #

    before(:each) do
      framework.data_store[key] = value
    end

    it "saves 'framework/core' to framework.pathnames.file" do
      save_config

      expect(framework.pathnames.file.read).to eq("[framework/core]\n#{key}=#{value}\n\n")
    end
  end
end