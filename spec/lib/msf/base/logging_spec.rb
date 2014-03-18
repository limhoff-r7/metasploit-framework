require 'spec_helper'

describe Msf::Logging do
  shared_context 'session' do
    #
    # lets
    #

    let(:log_file_name) do
      'log_file_name'
    end

    let(:log_source) do
      'session_log_source'
    end

    let(:session) do
      double(
          'Msf::Session',
          log_file_name: log_file_name,
          log_source: log_source
      )
    end

    #
    # Callbacks
    #

    before(:each) do
      logs_pathname.join('sessions').mkpath
    end
  end

  shared_context 'setup!' do
    #
    # lets
    #

    let(:logs_pathname) do
      Metasploit::Model::Spec.temporary_pathname.join('logs')
    end

    let(:options) do
      {
          logs_pathname: logs_pathname
      }
    end

    #
    # Callbacks
    #

    before(:each) do
      logs_pathname.mkpath
      described_class.setup!(options)
    end
  end

  include_context 'Msf::Logging'

  context 'disable_log_source' do
    subject(:disable_log_source) do
      described_class.disable_log_source(source)
    end

    let(:source) do
      'source'
    end

    it 'calls deregister_log_source' do
      expect(described_class).to receive(:deregister_log_source).with(source)

      disable_log_source
    end
  end

  context 'enable_log_source' do
    include_context 'setup!'

    subject(:enable_log_source) do
      described_class.enable_log_source(source, *arguments)
    end

    let(:arguments) do
      []
    end

    let(:source) do
      described_class.sources.sample
    end

    context 'with registered source' do
      specify {
        expect {
          enable_log_source
        }.not_to raise_error
      }
    end

    context 'without registered source' do
      let(:source) do
        'source'
      end

      it 'uses log file under logs_pathname called <source>.log' do
        expect(described_class).to receive(:register_log_source) do |_, sink, _|
          expect(sink.send(:fd).path).to eq(logs_pathname.join("#{source}.log").to_path)
        end

        enable_log_source
      end

      context 'with level' do
        let(:arguments) do
          [
              level
          ]
        end

        let(:level) do
          1
        end

        it 'registers source with level' do
          expect(described_class).to receive(:register_log_source).with(
                                         source,
                                         an_instance_of(Rex::Logging::Sinks::Flatfile),
                                         level
                                     )

          enable_log_source
        end
      end

      context 'without level' do
        it 'registers source with default level (0)' do
          expect(described_class).to receive(:register_log_source).with(
                                         source,
                                         an_instance_of(Rex::Logging::Sinks::Flatfile),
                                         0
                                     )

          enable_log_source
        end
      end
    end
  end

  context 'enable_session_logging' do
    subject(:enable_session_logging) do
      described_class.enable_session_logging(enable)
    end

    let(:enable) do
      true
    end

    after(:each) do
      described_class.send(:remove_instance_variable, :@session_logging)
    end

    it 'sets @session_logging' do
      expect {
        enable_session_logging
      }.to change {
        described_class.instance_variable_get(:@session_logging)
      }.to(enable)
    end
  end

  context 'logs_pathname' do
    subject(:logs_pathname) do
      described_class.logs_pathname
    end

    context 'with setup' do
      #
      # lets
      #

      let(:setup_logs_pathname) do
        Metasploit::Model::Spec.temporary_pathname.join('logs')
      end

      #
      # Callbacks
      #

      before(:each) do
        setup_logs_pathname.mkpath
        described_class.setup(logs_pathname: setup_logs_pathname)
      end

      it 'returns :logs_pathname passed to setup' do
        expect(logs_pathname).to eq(setup_logs_pathname)
      end
    end

    context 'without setup' do
      specify {
        expect {
          logs_pathname
        }.to raise_error Msf::Logging::NotSetup
      }
    end
  end

  context 'session_logging_enabled?' do
    subject(:session_logging_enabled?) do
      described_class.session_logging_enabled?
    end

    context 'default' do
      it { should be_false }
    end
  end

  context 'setup' do
    subject(:setup) do
      described_class.setup(options)
    end

    context 'with :logs_pathname' do
      #
      # lets
      #

      let(:logs_pathname) do
        Metasploit::Model::Spec.temporary_pathname.join('logs')
      end

      let(:options) do
        {
            logs_pathname: logs_pathname
        }
      end

      #
      # Callbacks
      #

      before(:each) do
        logs_pathname.mkpath
      end

      it 'sets logs_pathname' do
        setup

        expect(described_class.logs_pathname).to eq(logs_pathname)
      end

      it 'registers sources' do
        described_class.sources.each do |source|
          expect(described_class).to receive(:register_log_source).with(
                                         source,
                                         an_instance_of(Rex::Logging::Sinks::Flatfile)
                                     )
        end

        setup
      end

      it 'uses the same sink for all sources' do
        setup

        sink_set = described_class.sources.each_with_object(Set.new) { |source, set|
          set.add $dispatcher[source]
        }

        expect(sink_set).to have(1).item
      end

      context 'with called already' do
        before(:each) do
          described_class.setup(options)
        end

        it 'raises RunTime error because of duplicate sources' do
          expect {
            setup
          }.to raise_error RuntimeError
        end
      end
    end

    context 'without :logs_pathname' do
      let(:options) do
        {}
      end

      specify {
        expect {
          setup
        }.to raise_error KeyError
      }
    end
  end

  context 'setup!' do
    subject(:setup!) do
      described_class.setup!(options)
    end

    #
    # lets
    #

    let(:logs_pathname) do
      Metasploit::Model::Spec.temporary_pathname.join('logs')
    end

    let(:options) do
      {
          logs_pathname: logs_pathname
      }
    end

    #
    # Callbacks
    #

    before(:each) do
      logs_pathname.mkpath
    end

    context 'calling twice' do
      before(:each) do
        described_class.setup!(options)
      end

      context 'with teardown' do
        before(:each) do
          described_class.teardown
        end

        specify {
          expect {
            setup!
          }.not_to raise_error
        }
      end

      context 'without teardown' do
        specify {
          expect {
            setup!
          }.to raise_error Msf::Logging::AlreadySetup
        }
      end
    end
  end

  context 'sources' do
    subject(:sources) do
      described_class.sources
    end

    it { should include 'base' }
    it { should include Msf::LogSource }
    it { should include Rex::LogSource }
  end

  context 'start_session_log' do
    include_context 'session'
    include_context 'setup!'

    subject(:start_session_log) do
      described_class.start_session_log(session)
    end

    after(:each) do
      deregister_log_source(log_source)
    end

    context 'with registered' do
      before(:each) do
        described_class.start_session_log(session)
      end

      it 'does not re-register' do
        expect {
          start_session_log
        }.not_to receive(:register_log_source)
      end
    end

    context 'without registered' do
      it 'registers session.log_source' do
        expect(described_class).to receive(:register_log_source).with(session.log_source, anything)

        start_session_log
      end

      it 'opens log file under logs/sessions' do
        expect(described_class).to receive(:register_log_source) do |_, sink|
          path = sink.send(:fd).path

          expect(path).to start_with(logs_pathname.join('sessions', session.log_file_name).to_path)
        end

        start_session_log
      end

      it 'writes when the log was started to the session.log_source' do
        start_session_log

        sink = $dispatcher[log_source]

        open(sink.send(:fd).path, 'r') do |f|
          expect(f.read).to include('Logging started')
        end
      end
    end
  end

  context 'stop_session_log' do
    include_context 'session'
    include_context 'setup!'

    subject(:stop_session_log) do
      described_class.stop_session_log(session)
    end

    before(:each) do
      described_class.start_session_log(session)
    end

    it 'writes when the log was stopped to the session.log_source' do
      sink = $dispatcher[log_source]

      stop_session_log

      open(sink.send(:fd).path, 'r') do |f|
        expect(f.read).to include('Logging stopped')
      end
    end

    it 'deregisters session.log_source' do
      expect(described_class).to receive(:deregister_log_source).with(session.log_source).and_call_original

      stop_session_log
    end
  end

  context 'teardown' do
    subject(:teardown) do
      described_class.teardown
    end

    it 'sets source sinks to nil' do
      teardown

      described_class.sources.each do |source|
        $dispatcher.log_sinks_lock.synchronize do
          expect($dispatcher.log_sinks[source]).to be_nil
        end
      end
    end
  end
end