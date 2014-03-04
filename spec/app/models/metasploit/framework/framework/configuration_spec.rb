require 'spec_helper'

describe Metasploit::Framework::Framework::Configuration do
  subject(:configuration) do
    described_class.new(attributes)
  end

  let(:attributes) do
    {}
  end

  context 'CONSTANTS' do
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
  end

  context '#file_pathname' do
    subject(:file_pathname) do
      configuration.file_pathname
    end

    context 'with set' do
      let(:attributes) do
        {
            file_pathname: expected_file_pathname
        }
      end

      let(:expected_file_pathname) do
        Metasploit::Model::Spec.temporary_pathname.join('file')
      end

      it 'should use set value' do
        expect(file_pathname).to eq(expected_file_pathname)
      end
    end

    context 'without set' do
      let(:attributes) do
        {

            # set #root to ensure #root is being used instead of ::root
            root: root
        }
      end

      let(:root) do
        Metasploit::Model::Spec.temporary_pathname.join('root')
      end

      it 'should be FILE_BASE_NAME under #root' do
        expect(file_pathname).to eq(root.join(described_class::FILE_BASE_NAME))
      end
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
      configuration.root
    end

    context 'with set' do
      #
      # lets
      #

      let(:expected_root) do
        Pathname.new('root')
      end

      #
      # Callbacks
      #

      before(:each) do
        configuration.root = expected_root
      end

      it 'uses set value' do
        expect(root).to eq(expected_root)
      end
    end

    context 'without set' do
      it 'calls ::root' do
        expected = double('root')
        expect(described_class).to receive(:root).and_return(expected)
        expect(root).to eq(expected)
      end
    end
  end
end