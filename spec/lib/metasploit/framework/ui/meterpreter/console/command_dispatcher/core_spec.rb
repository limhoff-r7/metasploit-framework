require 'spec_helper'

describe Metasploit::Framework::UI::Meterpreter::Console::CommandDispatcher::Core do
  subject(:command_dispatcher) do
    described_class.new(shell)
  end

  let(:client) do
    double('client', framework: framework)
  end

  let(:framework) do
    nil
  end

  let(:shell) do
    double('shell', client: client)
  end

  context '#cmd_run_tabs' do
    #
    # Shared Examples
    #

    shared_examples_for 'populates tabs' do
      include_context 'database cleaner'
      include_context 'Metasploit::Framework::Spec::Constants cleaner'

      #
      # lets
      #

      let(:cache_post_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: 'post'
        )
      end

      #
      # let!s
      #

      let!(:cache_post_instance) do
        FactoryGirl.create(
            :mdm_module_instance,
            module_class: cache_post_class
        )
      end

      context 'with framework loaded' do
        include_context 'Msf::Simple::Framework'

        #
        # Callbacks
        #

        before(:each) do
          Msf::Post.any_instance.stub(session_compatible?: true)
        end

        it 'includes post module full names' do
          expect(cmd_run_tabs).to include(cache_post_class.full_name)
        end

        context 'with framework scripts pathname' do
          #
          # lets
          #

          let(:child) do
            parent.join("#{child_basename}#{child_extension}")
          end

          let(:child_basename) do
            'child'
          end

          let(:child_without_extension) do
            parent.join(child_basename)
          end

          let(:child_extension) do
            ''
          end

          let(:parent) do
            framework.pathnames.scripts.join(Msf::Sessions::Meterpreter.type)
          end

          #
          # Callbacks
          #

          before(:each) do
            parent.mkpath
          end

          context 'with directory' do
            before(:each) do
              child.mkpath
            end

            it 'does not include directory' do
              expect(cmd_run_tabs).not_to include(child.to_s)
            end
          end

          context 'with file' do
            #
            # lets
            #

            let(:child_extension) do
              '.rb'
            end

            #
            # Callbacks
            #

            before(:each) do
              child.open('wb') { |f|
                f.puts '# I am a script'
              }
            end

            context 'with readable' do
              it 'includes file without .rb extension' do
                expect(cmd_run_tabs).to include(child_without_extension.to_s)
              end
            end

            context 'without readable' do
              before(:each) do
                child.chmod(0222)
              end

              it 'does not include file' do
                expect(cmd_run_tabs).not_to include(child_without_extension.to_s)
              end
            end
          end

          it 'includes installation scripts' do
            expect {
              cmd_run_tabs.any? { |path|
                path.start_with? Metasploit::Framework.pathnames.scripts.join(Msf::Sessions::Meterpreter.type).to_s
              }
            }.to be_true
          end
        end
      end

      context 'without framework loaded' do
        it 'does not include post module full names' do
          expect(cmd_run_tabs).not_to include(cache_post_class.full_name)
        end

        it 'includes installation scripts' do
          expect {
            cmd_run_tabs.any? { |path|
              path.start_with? Metasploit::Framework.pathnames.scripts.join(Msf::Sessions::Meterpreter.type).to_s
            }
          }.to be_true
        end
      end
    end

    subject(:cmd_run_tabs) do
      command_dispatcher.cmd_run_tabs(partial_word, words)
    end

    let(:partial_word) do
      ''
    end

    context 'with words' do
      context "starting with '/'" do
        let(:words) do
          [
              'run',
              '/'
          ]
        end

        it { should be_empty }
      end

      context "not starting with '/'" do
        let(:words) do
          [
              'run',
              'second_word'
          ]
        end

        it_should_behave_like 'populates tabs'
      end
    end

    context 'without words' do
      let(:words) do
        []
      end

      it_should_behave_like 'populates tabs'
    end
  end

  context '#tab_complete_postmods' do
    include_context 'database cleaner'
    include_context 'Metasploit::Framework::Spec::Constants cleaner'
    include_context 'Msf::Simple::Framework'

    subject(:tab_complete_postmods) do
      command_dispatcher.send(:tab_complete_postmods)
    end

    #
    # lets
    #

    let(:cache_post_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: 'post'
      )
    end

    let(:cache_post_instance) do
      FactoryGirl.create(
          :mdm_module_instance,
          module_class: cache_post_class
      )
    end

    #
    # Callbacks
    #

    before(:each) do
      # rig it to return its normal value so that the return value can have expectations applied
      expect(framework.modules).to receive(:create_from_module_class).with(cache_post_class).and_return(post_instance)
    end

    context 'with created' do
      let(:post_instance) do
        framework.modules.create_from_module_class(cache_post_instance.module_class)
      end

      before(:each) do
        expect(post_instance).to receive(:session_compatible?).with(client).and_return(session_compatible)
      end

      context 'with compatible with session' do
        let(:session_compatible) do
          true
        end

        it 'includes Mdm::Module::Class#full_name' do
          expect(tab_complete_postmods).to include(cache_post_class.full_name)
        end
      end

      context 'without compatible with session' do
        let(:session_compatible) do
          false
        end

        it 'does not include nils as it confuses readline' do
          expect(tab_complete_postmods).not_to include(nil)
        end
      end
    end

    context 'without created' do
      let(:post_instance) do
        nil
      end

      it 'does not include nils as it confuses readline' do
        expect(tab_complete_postmods).not_to include(nil)
      end
    end
  end
end