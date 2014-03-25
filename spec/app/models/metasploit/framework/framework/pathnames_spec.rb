require 'spec_helper'

describe Metasploit::Framework::Framework::Pathnames do
  subject(:pathnames) do
    described_class.new(attributes)
  end

  let(:attributes) do
    {}
  end

  it { should be_frozen }

  context 'factories' do
    context 'metasploit_framework_framework_pathnames' do
      subject(:metasploit_framework_framework_pathnames) do
        FactoryGirl.build(:metasploit_framework_framework_pathnames)
      end

      context '#root' do
        subject(:root) do
          metasploit_framework_framework_pathnames.root
        end

        it 'is unique' do
          expect(root).not_to eq(described_class.root)
        end
      end
    end
  end

  context 'CONSTANTS' do
    context 'DIRECTORIES' do
      subject(:directories) do
        described_class::DIRECTORIES
      end

      it { should include 'data' }
      it { should include 'exploit_data' }
      it { should include 'local' }
      it { should include 'logs' }
      it { should include 'loot' }
      it { should include 'plugins' }
      it { should include 'modules' }
      it { should include 'root' }
      it { should include 'scripts' }
      it { should include 'script_logs' }
      it { should include 'session_logs' }
    end

    context 'FILE_BASE_NAME' do
      subject(:file_base_name) do
        described_class::FILE_BASE_NAME
      end

      it { should == 'config' }
    end

    context 'ROOT_BASE_NAME' do
      subject(:root_base_name) do
        described_class::ROOT_BASE_NAME
      end

      it { should == '.msf4' }
    end

    context 'ROOT_PARENT_ENVIRONMENT_VARIABLES' do
      subject(:root_parent_environment_variables) do
        described_class::ROOT_PARENT_ENVIRONMENT_VARIABLES
      end

      it { should == ['HOME', 'LOCALAPPDATA', 'APPDATA', 'USERPROFILE'] }
    end

    context 'SUBDIRECTORIES' do
      subject(:subdirectories) do
        described_class::SUBDIRECTORIES
      end

      it { should include 'data' }
      it { should include 'local' }
      it { should include 'logs' }
      it { should include 'loot' }
      it { should include 'plugins' }
      it { should include 'modules' }
      it { should include 'scripts' }
    end
  end

  context '#data' do
    subject(:data) do
      pathnames.data
    end

    it 'is <root>/data' do
      expect(data).to eq(pathnames.root.join('data'))
    end
  end

  context '#database_yaml' do
    subject(:database_yaml) do
      pathnames.database_yaml
    end

    #
    # lets
    #

    let(:environment_variable) do
      'MSF_DATABASE_CONFIG'
    end

    #
    # Callbacks
    #

    around(:each) do |example|
      before = ENV.delete(environment_variable)

      begin
        example.run
      ensure
        ENV[environment_variable] = before
      end
    end

    context 'with MSF_DATABASE_CONFIG environment variable' do
      #
      # lets
      #

      let(:expected_database_yaml) do
        Metasploit::Model::Spec.temporary_pathname.join('database.yml')
      end

      #
      # Callbacks
      #

      before(:each) do
        ENV[environment_variable] = expected_database_yaml.to_path
      end

      it 'uses MSF_DATABASE_CONFIG' do
        expect(database_yaml).to eq(expected_database_yaml)
      end
    end

    context 'without MSF_DATABASE_CONFIG environment variable' do
      it 'use <root>/database.yml' do
        expect(database_yaml).to eq(pathnames.root.join('database.yml'))
      end
    end
  end

  context '#exploit_data' do
    subject(:exploit_data) do
      pathnames.exploit_data
    end

    it 'is <data>/exploits' do
      expect(exploit_data).to eq(pathnames.data.join('exploits'))
    end
  end

  context '#file' do
    subject(:file) do
      pathnames.file
    end

    it 'is <root>/config' do
      expect(file).to eq(pathnames.root.join('config'))
    end
  end

  context '#history' do
    subject(:history) do
      pathnames.history
    end

    it 'is <root>/history' do
      expect(history).to eq(pathnames.root.join('history'))
    end
  end

  context '#local' do
    subject(:local) do
      pathnames.local
    end

    it 'is <root>/local' do
      expect(local).to eq(pathnames.root.join('local'))
    end
  end

  context '#logs' do
    subject(:logs) do
      pathnames.logs
    end

    it 'is <root>/logs' do
      expect(logs).to eq(pathnames.root.join('logs'))
    end
  end

  context '#loot' do
    subject(:loot) do
      pathnames.loot
    end

    it 'is <root>/loot' do
      expect(loot).to eq(pathnames.root.join('loot'))
    end
  end

  context '#make' do
    subject(:make) do
      pathnames.make
    end

    #
    # lets
    #

    let(:attributes) do
      {
          root: root
      }
    end

    let(:root) do
      Metasploit::Model::Spec.temporary_pathname.join('root')
    end

    %w{local logs loot plugins modules root scripts script_logs session_logs}.each do |directory|
      it "makes ##{directory}" do
        expect {
          make
        }.to change(pathnames.local, :exist?).to(true)
      end
    end
  end

  context '#modules' do
    subject(:modules) do
      pathnames.modules
    end

    it 'is <root>/modules' do
      expect(modules).to eq(pathnames.root.join('modules'))
    end
  end

  context '#plugins' do
    subject(:plugins) do
      pathnames.plugins
    end

    it 'is <root>/plugins' do
      expect(plugins).to eq(pathnames.root.join('plugins'))
    end
  end

  context 'root' do
    subject(:root) do
      described_class.root
    end

    #
    # lets
    #

    let(:environment_variables) do
      ['APPDATA', 'HOME', 'LOCALAPPDATA', 'MSF_CFGROOT_CONFIG', 'USERPROFILE']
    end

    let(:pathname_by_environment_variable) do
      environment_variables.each_with_object({}) { |environment_variable, hash|
        hash[environment_variable] = Metasploit::Model::Spec.temporary_pathname.join(
            environment_variable.underscore
        )
      }
    end

    #
    # Callbacks
    #

    around(:each) do |example|
      value_by_environment_variable = {}

      environment_variables.each do |environment_variable|
        value_by_environment_variable[environment_variable] = ENV.delete(environment_variable)
      end

      begin
        example.run
      ensure
        value_by_environment_variable.each do |environment_variable, value|
          ENV[environment_variable] = value
        end
      end
    end

    before(:each) do
      pathname_by_environment_variable.each do |environment_variable, pathname|
        pathname.join('.msf4').mkpath

        ENV[environment_variable] = pathname.to_path
      end
    end

    context 'with environment variables' do
      let(:pathname) do
        pathname_by_environment_variable[environment_variable]
      end

      context 'with MSF_CFGROOT_CONFIG' do
        let(:environment_variable) do
          'MSF_CFGROOT_CONFIG'
        end

        #
        # Callbacks
        #

        context 'with directory' do
          it 'is MSF_CFGROOT_CONFIG' do
            expect(root).to eq(pathname)
          end
        end

        context 'without directory' do
          before(:each) do
            pathname.rmtree
          end

          it 'is not MSF_CFGROOT_CONFIG' do
            expect(root).not_to eq(pathname)
          end
        end
      end

      context 'without MSF_CFGROOT_CONFIG' do
        #
        # lets
        #

        let(:environment_variable_root) do
          pathname.join('.msf4')
        end

        #
        # Callbacks
        #

        before(:each) do
          ENV.delete('MSF_CFGROOT_CONFIG')
        end

        context 'with HOME' do
          let(:environment_variable) do
            'HOME'
          end

          #
          # Callbacks
          #

          context 'with directory' do
            it 'is <HOME>/.msf4' do
              expect(root).to eq(environment_variable_root)
            end
          end

          context 'without directory' do
            before(:each) do
              pathname.rmtree
            end

            it 'is not <HOME>/.msf4' do
              expect(root).not_to eq(environment_variable_root)
            end
          end
        end

        context 'without HOME' do
          before(:each) do
            ENV.delete('HOME')
          end

          context 'with LOCALAPPDATA' do
            let(:environment_variable) do
              'LOCALAPPDATA'
            end

            #
            # Callbacks
            #

            context 'with directory' do
              it 'is <LOCALAPPDATA>/.msf4' do
                expect(root).to eq(environment_variable_root)
              end
            end

            context 'without directory' do
              before(:each) do
                pathname.rmtree
              end

              it 'is not <LOCALAPPDATA>/.msf4' do
                expect(root).not_to eq(environment_variable_root)
              end
            end
          end

          context 'without LOCALAPPDATA' do
            before(:each) do
              ENV.delete('LOCALAPPDATA')
            end

            context 'with APPDATA' do
              let(:environment_variable) do
                'APPDATA'
              end

              #
              # Callbacks
              #

              context 'with directory' do
                it 'is <APPDATA>/.msf4' do
                  expect(root).to eq(environment_variable_root)
                end
              end

              context 'without directory' do
                before(:each) do
                  pathname.rmtree
                end

                it 'is not <APPDATA>/.msf4' do
                  expect(root).not_to eq(environment_variable_root)
                end
              end
            end

            context 'without APPDATA' do
              before(:each) do
                ENV.delete('APPDATA')
              end

              context 'with USERPROFILE' do
                let(:environment_variable) do
                  'USERPROFILE'
                end

                #
                # Callbacks
                #

                context 'with directory' do
                  it 'is <USERPROFILE>/.msf4' do
                    expect(root).to eq(environment_variable_root)
                  end
                end

                context 'without directory' do
                  before(:each) do
                    pathname.rmtree
                  end

                  it 'is not <USERPROFILE>/.msf4' do
                    expect(root).not_to eq(environment_variable_root)
                  end
                end
              end

              context 'without USERPROFILE' do
                before(:each) do
                  ENV.delete('USERPROFILE')
                end

                context 'with ~ directory' do
                  #
                  # lets
                  #

                  let(:home_pathname) do
                    Metasploit::Model::Spec.temporary_pathname.join('home')
                  end

                  #
                  # Callbacks
                  #

                  before(:each) do
                    expect(Dir).to receive(:home).and_return(home_pathname.to_path)
                  end

                  it 'is ~/<ROOT_BASE_NAME>' do
                    expect(root).to eq(home_pathname.join(described_class::ROOT_BASE_NAME))
                  end
                end

                context 'without ~ directory' do
                  before(:each) do
                    expect(Dir).to receive(:home).and_raise(ArgumentError)
                  end

                  it 'is ROOT_BASE_NAME under Metasploit::Framework.root' do
                    expect(root).to eq(Metasploit::Framework.root.join(described_class::ROOT_BASE_NAME))
                  end
                end
              end
            end
          end
        end
      end
    end
  end

  context '#root' do
    subject(:root) do
      pathnames.root
    end

    context 'with set' do
      #
      # lets
      #

      let(:attributes) do
        {
            root: expected_root
        }
      end

      let(:expected_root) do
        Metasploit::Model::Spec.temporary_pathname.join('root')
      end

      #
      # Callbacks
      #

      before(:each) do
        expected_root.mkpath
      end

      it 'uses set value' do
        expect(root).to eq(expected_root)
      end
    end

    context 'without set' do
      it 'calls ::root' do
        expected = described_class.root
        expect(described_class).to receive(:root).and_return(expected)
        expect(root).to eq(expected)
      end
    end
  end

  context '#scripts' do
    subject(:scripts) do
      pathnames.scripts
    end

    it 'is <root>/scripts' do
      expect(scripts).to eq(pathnames.root.join('scripts'))
    end
  end

  context '#script_logs' do
    subject(:script_logs) do
      pathnames.script_logs
    end

    it 'is <logs>/scripts' do
      expect(script_logs).to eq(pathnames.logs.join('scripts'))
    end
  end

  context '#session_logs' do
    subject(:session_logs) do
      pathnames.session_logs
    end

    it 'is <logs>/sessions' do
      expect(session_logs).to eq(pathnames.logs.join('sessions'))
    end
  end
end