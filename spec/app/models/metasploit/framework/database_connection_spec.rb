require 'spec_helper'

describe Metasploit::Framework::DatabaseConnection do
  include_context 'Msf::DBManager'

  subject(:database_connection) do
    described_class.new(
        environment: environment,
        framework: framework
    )
  end

  let(:environment) do
    Metasploit::Framework.env
  end

  context 'validations' do
    context 'for #configuration' do
      subject(:configuration_errors) do
        database_connection.errors[:configuration]
      end

      let(:error) do
        I18n.translate!('errors.messages.blank')
      end

      context 'with {}' do
        before(:each) do
          allow(database_connection).to receive(:configuration).and_return({})

          database_connection.valid?
        end

        it { should include error }
      end

      context 'without empty' do
        it { should_not include error }
      end
    end

    context 'for #connected?' do
      subject(:connected_errors) do
        database_connection.errors[:connected?]
      end

      #
      # lets
      #

      let(:error) do
        I18n.translate!('metasploit.model.errors.models.metasploit/framework/database_connection.attributes.connected?.inclusion')
      end

      #
      # Callbacks
      #

      before(:each) do
        allow(database_connection).to receive(:connected?).and_return(connected)

        database_connection.valid?
      end

      context 'with false' do
        let(:connected) do
          false
        end

        it { should include error }
      end

      context 'with true' do
        let(:connected) do
          true
        end

        it { should_not include error }
      end
    end

    context 'for #database_yaml_pathname' do
      subject(:database_yaml_pathname_errors) do
        database_connection.errors[:database_yaml_pathname]
      end

      let(:database_yaml_pathname) do
        database_connection.database_yaml_pathname
      end

      context '#database_yaml_pathname_exists' do
        let(:error) do
          I18n.translate!('metasploit.model.errors.models.metasploit/framework/database_connection.attributes.database_yaml_pathname.non_existent')
        end

        context 'with existent file' do
          before(:each) do
            database_yaml_pathname.open('w') do |f|
              f.puts "#{environment}:\n"
            end

            database_connection.valid?
          end

          it { should_not include(error) }
        end

        context 'with non-existent file' do
          before(:each) do
            database_yaml_pathname.delete

            database_connection.valid?
          end

          it { should include(error) }
        end
      end

      context '#database_yaml_pathname_readable' do
        #
        # lets
        #

        let(:error) do
          I18n.translate!('metasploit.model.errors.models.metasploit/framework/database_connection.attributes.database_yaml_pathname.unreadable')
        end

        #
        # Callbacks
        #

        before(:each) do
          database_yaml_pathname.open('w') do |f|
            f.puts "#{environment}:\n"
          end
        end

        context 'with readable file' do
          before(:each) do
            database_connection.valid?
          end

          it { should_not include(error) }
        end

        context 'without readable file' do
          before(:each) do
            database_yaml_pathname.chmod(0222)

            database_connection.valid?
          end

          it { should include(error) }
        end
      end
    end

    context 'for #db_manager' do
      context '#db_manager_valid' do
        subject(:db_manager_errors) do
          database_connection.errors[:db_manager]
        end

        let(:error) do
          I18n.translate!('errors.messages.invalid')
        end

        context 'with #db_manager' do
          context 'with valid' do
            it { should_not include(error) }
          end

          context 'without valid' do
            before(:each) do
              allow(db_manager).to receive(:valid?).and_return(false)

              database_connection.valid?
            end

            it { should include(error) }
          end
        end

        context 'without #db_manager' do
          before(:each) do
            database_connection.framework = nil

            database_connection.valid?
          end

          it { should_not include(error) }
        end
      end
    end

    it { should validate_presence_of :framework }
  end

  context '#configuration' do
    subject(:configuration) do
      database_connection.configuration
    end

    it 'looks up environment in #configuration_by_environment' do
      expect(configuration).to eq(database_connection.configuration_by_environment[environment])
    end
  end

  context '#configuration_by_environment' do
    subject(:configuration_by_environment) do
      database_connection.configuration_by_environment
    end

    let(:database_yaml_pathname) do
      database_connection.database_yaml_pathname
    end

    context 'with non-existent path' do
      before(:each) do
        database_yaml_pathname.delete
      end

      it { should == {} }
    end

    context 'with unreadable path' do
      before(:each) do
        # remove read permissions
        database_yaml_pathname.chmod(0222)
      end

      it { should == {} }
    end

    context 'with ERB' do
      before(:each) do
        database_yaml_pathname.open('w') do |f|
          f.write "<%= \"#{environment}:\n  option: 1\" %>"
        end
      end

      it 'should convert ERB to YAML' do
        expect(configuration_by_environment).to eq(
                                                    {
                                                        environment => {
                                                            'option' => 1
                                                        }
                                                    }
                                                )
      end
    end

    context 'without ERB' do
      before(:each) do
        database_yaml_pathname.open('w') do |f|
          f.write "#{environment}:\n  option: 1"
        end
      end

      it 'should convert to Hash' do
        expect(configuration_by_environment).to eq(
                                                    {
                                                      environment => {
                                                          'option' => 1
                                                      }
                                                    }

                                                )
      end
    end
  end

  context 'connected?' do
    subject(:connected?) do
      database_connection.connected?
    end

    context 'with #db_manager' do
      shared_examples_for 'delegates to #db_manager' do
        it 'does not attempt to connect' do
          expect(db_manager).not_to receive(:connect)

          connected?
        end

        it 'asks #db_manager if it is connected' do
          expect(db_manager).to receive(:connected?)

          connected?
        end
      end

      context 'with valid' do
        context 'with #configuration' do
          it 'attempts to connect' do
            expect(db_manager).to receive(:connect).with(database_connection.configuration)

            connected?
          end
        end

        context 'without #configuration' do
          before(:each) do
            allow(database_connection).to receive(:configuration).and_return({})
          end

          it_should_behave_like 'delegates to #db_manager'
        end
      end

      context 'without valid' do
        before(:each) do
          allow(db_manager).to receive(:valid?).and_return(false)
        end

        it_should_behave_like 'delegates to #db_manager'
      end
    end

    context 'without #db_manager' do
      before(:each) do
        database_connection.framework = nil
      end

      it { should be_false }
    end
  end

  context '#database_yaml_pathname' do
    subject(:database_yaml_pathname) do
      database_connection.database_yaml_pathname
    end

    context 'with #framework' do
      it 'is framework.pathanmes.database_yaml' do
        expect(database_yaml_pathname).to eq(framework.pathnames.database_yaml)
      end
    end

    context 'without #framework' do
      let(:framework) do
        nil
      end

      it { should be_nil }
    end
  end

  context '#environment' do
    subject(:actual_environment) do
      database_connection.environment
    end

    let(:environment) do
      nil
    end

    it 'defaults to Metasploit::Framework.env' do
      expected = double('env')
      expect(Metasploit::Framework).to receive(:env).and_return(expected)
      expect(actual_environment).to eq(expected)
    end
  end

  context '#environment=' do
    subject(:actual_environment) do
      database_connection.environment
    end

    before(:each) do
      database_connection.environment = input_environment
    end

    context 'with nil' do
      let(:input_environment) do
        nil
      end

      it 'uses default environment' do
        expect(actual_environment).to eq(Metasploit::Framework.env)
      end
    end

    context 'without nil' do
      let(:input_environment) do
        'a_string'
      end

      it 'wraps input in ActiveSupport::StringInquirer' do
        expect(actual_environment).to be_a ActiveSupport::StringInquirer
        expect(actual_environment).to eq(input_environment)
      end
    end
  end
end