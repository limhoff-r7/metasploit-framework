require 'spec_helper'

load Metasploit::Framework.root.join('msfcli').to_path

require 'msfenv'
require 'msf/ui'
require 'msf/base'


describe Msfcli do
  include_context 'Msf::Simple::Framework'

  subject(:msfcli) do
    Msfcli.new(args).tap { |msfcli|
      msfcli.framework = framework
    }
  end

  let(:args) do
    []
  end

  # Get stdout:
  # http://stackoverflow.com/questions/11349270/test-output-to-command-line-with-rspec
  def get_stdout(&block)
    out = $stdout
    $stdout = fake = StringIO.new
    begin
      yield
    ensure
      $stdout = out
    end
    fake.string
  end

  #
  # This one is slow because we're loading all modules
  #
  context "#dump_module_list" do
    include_context 'database cleaner'

    subject(:dump_module_list) do
      msfcli.dump_module_list
    end

    #
    # lets
    #

    let(:cache_auxiliary_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: 'auxiliary'
      )
    end

    let(:cache_exploit_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: 'exploit'
      )
    end

    #
    # let!s
    #

    let!(:cache_auxiliary_instance) do
      FactoryGirl.create(
          :mdm_module_instance,
          module_class: cache_auxiliary_class
      )
    end

    let!(:cache_exploit_instance) do
      FactoryGirl.create(
          :mdm_module_instance,
          module_class: cache_exploit_class
      )
    end

    context 'auxiliary' do
      it 'includes title' do
        expect(msfcli.dump_module_list).to include('Auxiliary')
      end

      it 'includes module_class.full_name' do
        expect(msfcli.dump_module_list).to include(cache_auxiliary_class.full_name)
      end

      it 'includes name' do
        expect(msfcli.dump_module_list).to include(cache_auxiliary_instance.name)
      end
    end

    context 'exploit' do
      it 'includes title' do
        expect(msfcli.dump_module_list).to include('Exploits')
      end

      it 'includes module_class.full_name' do
        expect(msfcli.dump_module_list).to include(cache_exploit_class.full_name)
      end

      it 'includes name' do
        expect(msfcli.dump_module_list).to include(cache_exploit_instance.name)
      end
    end
  end

  context "#initialize" do
    it "should give me the correct module name in key :module_name after object initialization" do
      args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
      cli = Msfcli.new(args.split(' '))
      cli.instance_variable_get(:@args)[:module_name].should eq('multi/handler')
    end

    it "should give me the correct mode in key :mode after object initialization" do
      args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
      cli = Msfcli.new(args.split(' '))
      cli.instance_variable_get(:@args)[:mode].should eq('E')
    end

    it "should give me the correct module parameters after object initialization" do
      args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
      cli = Msfcli.new(args.split(' '))
      cli.instance_variable_get(:@args)[:params].should eq(['payload=windows/meterpreter/reverse_tcp', 'lhost=127.0.0.1'])
    end

    it "should give me an exploit name without the prefix 'exploit'" do
      args = "exploit/windows/browser/ie_cbutton_uaf payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
      cli = Msfcli.new(args.split(' '))
      cli.instance_variable_get(:@args)[:module_name].should eq("windows/browser/ie_cbutton_uaf")
    end

    it "should give me an exploit name without the prefix 'exploits'" do
      args = "exploits/windows/browser/ie_cbutton_uaf payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
      cli = Msfcli.new(args.split(' '))
      cli.instance_variable_get(:@args)[:module_name].should eq("windows/browser/ie_cbutton_uaf")
    end

    it "should set mode 's' (summary)" do
      args = "multi/handler payload=windows/meterpreter/reverse_tcp s"
      cli = Msfcli.new(args.split(' '))
      cli.instance_variable_get(:@args)[:mode].should eq('s')
    end

    it "should set mode 'h' (help) as default" do
      args = "multi/handler"
      cli = Msfcli.new(args.split(' '))
      cli.instance_variable_get(:@args)[:mode].should eq('h')
    end
  end

  context "#init_modules", pending: 'Push into argument parsing and *_instance readers' do
    it "should have multi/handler module initialized" do
      args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
      m    = ''
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
      }

      m[:module].class.to_s.should =~ /^Msf::Modules::/
    end

    it "should have my payload windows/meterpreter/reverse_tcp initialized" do
      args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
      m    = ''
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
      }

      m[:payload].class.to_s.should =~ /<Class:/
    end

    it "should have my modules initialized with the correct parameters" do
      args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
      m    = ''
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
      }

      m[:module].datastore['lhost'].should eq("127.0.0.1")
    end

    it "should give me an empty hash as a result of an invalid module name" do
      args = "WHATEVER payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
      m    = ''
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
      }

      m.should eq({})
    end
  end

  context '#show_advanced' do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'
    include_context 'output'

    subject(:show_advanced) do
      msfcli.show_advanced
    end

    #
    # lets
    #

    let(:cache_auxiliary_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: 'auxiliary'
      )
    end

    let(:cache_auxiliary_instance) do
      FactoryGirl.create(
          :mdm_module_instance,
          module_class: cache_auxiliary_class
      )
    end

    let(:auxiliary_instance) do
      framework.modules.create_from_module_class(cache_auxiliary_instance.module_class).tap { |auxiliary_instance|
        expect(auxiliary_instance).not_to be_nil
      }
    end

    #
    # Callbacks
    #

    before(:each) do
      msfcli.auxiliary_instance = auxiliary_instance
    end

    it 'calls Msf::Seralizer::ReadableText.dump_advanced_options' do
      expect(Msf::Serializer::ReadableText).to receive(:dump_advanced_options).with(
                                                   auxiliary_instance,
                                                   described_class::INDENT
                                               ).and_call_original

      quietly
    end

    context 'with #payload_instance' do
      #
      # lets
      #

      let(:cache_payload_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: 'payload'
        )
      end

      let(:cache_payload_instance) do
        FactoryGirl.create(
            :mdm_module_instance,
            module_class: cache_payload_class
        )
      end

      let(:payload_instance) do
        framework.modules.create_from_module_class(cache_payload_instance.module_class).tap { |payload_instance|
          expect(payload_instance).not_to be_nil
        }
      end

      #
      # Callbacks
      #

      before(:each) do
        msfcli.payload_instance = payload_instance

        expect(Msf::Serializer::ReadableText).to receive(:dump_advanced_options).with(
                                                     auxiliary_instance,
                                                     described_class::INDENT
                                                 )
      end

      it 'calls Msf::Seralizer::ReadableText.dump_advanced_options' do
        expect(Msf::Serializer::ReadableText).to receive(:dump_advanced_options).with(
                                                     payload_instance,
                                                     described_class::INDENT
                                                 ).and_call_original

        quietly
      end
    end

    context 'with #encoder_instance' do
      #
      # lets
      #

      let(:cache_encoder_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: 'encoder'
        )
      end

      let(:cache_encoder_instance) do
        FactoryGirl.create(
            :mdm_module_instance,
            module_class: cache_encoder_class
        )
      end

      let(:encoder_instance) do
        framework.modules.create_from_module_class(cache_encoder_instance.module_class).tap { |encoder_instance|
          expect(encoder_instance).not_to be_nil
        }
      end

      #
      # Callbacks
      #

      before(:each) do
        msfcli.encoder_instance = encoder_instance

        expect(Msf::Serializer::ReadableText).to receive(:dump_advanced_options).with(
                                                     auxiliary_instance,
                                                     described_class::INDENT
                                                 )
      end

      it 'calls Msf::Seralizer::ReadableText.dump_advanced_options' do
        expect(Msf::Serializer::ReadableText).to receive(:dump_advanced_options).with(
                                                     encoder_instance,
                                                     described_class::INDENT
                                                 ).and_call_original

        quietly
      end
    end

    context 'with #nop_instance' do
      #
      # lets
      #

      let(:cache_nop_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: 'nop'
        )
      end

      let(:cache_nop_instance) do
        FactoryGirl.create(
            :mdm_module_instance,
            module_class: cache_nop_class
        )
      end

      let(:nop_instance) do
        framework.modules.create_from_module_class(cache_nop_instance.module_class).tap { |nop_instance|
          expect(nop_instance).not_to be_nil
        }
      end

      #
      # Callbacks
      #

      before(:each) do
        msfcli.nop_instance = nop_instance

        expect(Msf::Serializer::ReadableText).to receive(:dump_advanced_options).with(
                                                     auxiliary_instance,
                                                     described_class::INDENT
                                                 )
      end

      it 'calls Msf::Seralizer::ReadableText.dump_advanced_options' do
        expect(Msf::Serializer::ReadableText).to receive(:dump_advanced_options).with(
                                                     nop_instance,
                                                     described_class::INDENT
                                                 ).and_call_original

        quietly
      end
    end
  end

  context '#show_ids_evasion' do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'
    include_context 'output'

    subject(:show_ids_evasion) do
      msfcli.show_ids_evasion
    end

    #
    # lets
    #

    let(:cache_auxiliary_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: 'auxiliary'
      )
    end

    let(:cache_auxiliary_instance) do
      FactoryGirl.create(
          :mdm_module_instance,
          module_class: cache_auxiliary_class
      )
    end

    let(:auxiliary_instance) do
      framework.modules.create_from_module_class(cache_auxiliary_instance.module_class).tap { |auxiliary_instance|
        expect(auxiliary_instance).not_to be_nil
      }
    end

    #
    # Callbacks
    #

    before(:each) do
      msfcli.auxiliary_instance = auxiliary_instance
    end

    it 'calls Msf::Seralizer::ReadableText.dump_evasion_options' do
      expect(Msf::Serializer::ReadableText).to receive(:dump_evasion_options).with(
                                                   auxiliary_instance,
                                                   described_class::INDENT
                                               ).and_call_original

      quietly
    end

    context 'with #payload_instance' do
      #
      # lets
      #

      let(:cache_payload_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: 'payload'
        )
      end

      let(:cache_payload_instance) do
        FactoryGirl.create(
            :mdm_module_instance,
            module_class: cache_payload_class
        )
      end

      let(:payload_instance) do
        framework.modules.create_from_module_class(cache_payload_instance.module_class).tap { |payload_instance|
          expect(payload_instance).not_to be_nil
        }
      end

      #
      # Callbacks
      #

      before(:each) do
        msfcli.payload_instance = payload_instance

        expect(Msf::Serializer::ReadableText).to receive(:dump_evasion_options).with(
                                                     auxiliary_instance,
                                                     described_class::INDENT
                                                 )
      end

      it 'calls Msf::Seralizer::ReadableText.dump_evasion_options' do
        expect(Msf::Serializer::ReadableText).to receive(:dump_evasion_options).with(
                                                     payload_instance,
                                                     described_class::INDENT
                                                 ).and_call_original

        quietly
      end
    end

    context 'with #encoder_instance' do
      #
      # lets
      #

      let(:cache_encoder_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: 'encoder'
        )
      end

      let(:cache_encoder_instance) do
        FactoryGirl.create(
            :mdm_module_instance,
            module_class: cache_encoder_class
        )
      end

      let(:encoder_instance) do
        framework.modules.create_from_module_class(cache_encoder_instance.module_class).tap { |encoder_instance|
          expect(encoder_instance).not_to be_nil
        }
      end

      #
      # Callbacks
      #

      before(:each) do
        msfcli.encoder_instance = encoder_instance

        expect(Msf::Serializer::ReadableText).to receive(:dump_evasion_options).with(
                                                     auxiliary_instance,
                                                     described_class::INDENT
                                                 )
      end

      it 'calls Msf::Seralizer::ReadableText.dump_evasion_options' do
        expect(Msf::Serializer::ReadableText).to receive(:dump_evasion_options).with(
                                                     encoder_instance,
                                                     described_class::INDENT
                                                 ).and_call_original

        quietly
      end
    end

    context 'with #nop_instance' do
      #
      # lets
      #

      let(:cache_nop_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: 'nop'
        )
      end

      let(:cache_nop_instance) do
        FactoryGirl.create(
            :mdm_module_instance,
            module_class: cache_nop_class
        )
      end

      let(:nop_instance) do
        framework.modules.create_from_module_class(cache_nop_instance.module_class).tap { |nop_instance|
          expect(nop_instance).not_to be_nil
        }
      end

      #
      # Callbacks
      #

      before(:each) do
        msfcli.nop_instance = nop_instance

        expect(Msf::Serializer::ReadableText).to receive(:dump_evasion_options).with(
                                                     auxiliary_instance,
                                                     described_class::INDENT
                                                 )
      end

      it 'calls Msf::Seralizer::ReadableText.dump_evasion_options' do
        expect(Msf::Serializer::ReadableText).to receive(:dump_evasion_options).with(
                                                     nop_instance,
                                                     described_class::INDENT
                                                 ).and_call_original

        quietly
      end
    end
  end

  context '#show_summary' do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'
    include_context 'output'

    subject(:show_summary) do
      msfcli.show_summary
    end

    #
    # lets
    #

    let(:cache_auxiliary_class) do
      FactoryGirl.create(
          :mdm_module_class,
          module_type: 'auxiliary'
      )
    end

    let(:cache_auxiliary_instance) do
      FactoryGirl.create(
          :mdm_module_instance,
          module_class: cache_auxiliary_class
      )
    end

    let(:auxiliary_instance) do
      framework.modules.create_from_module_class(cache_auxiliary_instance.module_class).tap { |auxiliary_instance|
        expect(auxiliary_instance).not_to be_nil
      }
    end

    #
    # Callbacks
    #

    before(:each) do
      msfcli.auxiliary_instance = auxiliary_instance
    end

    it 'calls Msf::Seralizer::ReadableText.dump_module' do
      expect(Msf::Serializer::ReadableText).to receive(:dump_module).with(
                                                   auxiliary_instance,
                                                   described_class::INDENT
                                               ).and_call_original

      quietly
    end

    context 'with #payload_instance' do
      #
      # lets
      #

      let(:cache_payload_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: 'payload'
        )
      end

      let(:cache_payload_instance) do
        FactoryGirl.create(
            :mdm_module_instance,
            module_class: cache_payload_class
        )
      end

      let(:payload_instance) do
        framework.modules.create_from_module_class(cache_payload_instance.module_class).tap { |payload_instance|
          expect(payload_instance).not_to be_nil
        }
      end

      #
      # Callbacks
      #

      before(:each) do
        msfcli.payload_instance = payload_instance

        expect(Msf::Serializer::ReadableText).to receive(:dump_module).with(
                                                     auxiliary_instance,
                                                     described_class::INDENT
                                                 )
      end

      it 'calls Msf::Seralizer::ReadableText.dump_module' do
        expect(Msf::Serializer::ReadableText).to receive(:dump_module).with(
                                                     payload_instance,
                                                     described_class::INDENT
                                                 ).and_call_original

        quietly
      end
    end

    context 'with #encoder_instance' do
      #
      # lets
      #

      let(:cache_encoder_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: 'encoder'
        )
      end

      let(:cache_encoder_instance) do
        FactoryGirl.create(
            :mdm_module_instance,
            module_class: cache_encoder_class
        )
      end

      let(:encoder_instance) do
        framework.modules.create_from_module_class(cache_encoder_instance.module_class).tap { |encoder_instance|
          expect(encoder_instance).not_to be_nil
        }
      end

      #
      # Callbacks
      #

      before(:each) do
        msfcli.encoder_instance = encoder_instance

        expect(Msf::Serializer::ReadableText).to receive(:dump_module).with(
                                                     auxiliary_instance,
                                                     described_class::INDENT
                                                 )
      end

      it 'calls Msf::Seralizer::ReadableText.dump_module' do
        expect(Msf::Serializer::ReadableText).to receive(:dump_module).with(
                                                     encoder_instance,
                                                     described_class::INDENT
                                                 ).and_call_original

        quietly
      end
    end

    context 'with #nop_instance' do
      #
      # lets
      #

      let(:cache_nop_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: 'nop'
        )
      end

      let(:cache_nop_instance) do
        FactoryGirl.create(
            :mdm_module_instance,
            module_class: cache_nop_class
        )
      end

      let(:nop_instance) do
        framework.modules.create_from_module_class(cache_nop_instance.module_class).tap { |nop_instance|
          expect(nop_instance).not_to be_nil
        }
      end

      #
      # Callbacks
      #

      before(:each) do
        msfcli.nop_instance = nop_instance

        expect(Msf::Serializer::ReadableText).to receive(:dump_module).with(
                                                     auxiliary_instance,
                                                     described_class::INDENT
                                                 )
      end

      it 'calls Msf::Seralizer::ReadableText.dump_module' do
        expect(Msf::Serializer::ReadableText).to receive(:dump_module).with(
                                                     nop_instance,
                                                     described_class::INDENT
                                                 ).and_call_original

        quietly
      end
    end
  end

  context "#usage" do
    include_context 'output'

    subject(:usage) do
      msfcli.usage
    end

    it "should see a help menu" do
      expect(output).to include('Usage')
    end
  end

  pending 'Msfcli#engate_module connects to database to access module cache' do
    context "#engage_mode" do
      it "should show me the summary of module auxiliary/scanner/http/http_version" do
        args = 'auxiliary/scanner/http/http_version s'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }

        stdout.should =~ /Module: auxiliary\/scanner\/http\/http_version/
      end

      it "should show me the options of module auxiliary/scanner/http/http_version" do
        args = 'auxiliary/scanner/http/http_version O'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }

        stdout.should =~ /The target address range or CIDR identifier/
      end

      it "should me the advanced options of module auxiliary/scanner/http/http_version" do
        args = 'auxiliary/scanner/http/http_version A'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }

        stdout.should =~ /UserAgent/
      end

      it "should show me the IDS options of module auxiliary/scanner/http/http_version" do
        args = 'auxiliary/scanner/http/http_version I'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /Insert fake relative directories into the uri/
      end

      it "should show me the targets available for module windows/browser/ie_cbutton_uaf" do
        args = "windows/browser/ie_cbutton_uaf T"
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /IE 8 on Windows 7/
      end

      it "should show me the payloads available for module windows/browser/ie_cbutton_uaf" do
        args = "windows/browser/ie_cbutton_uaf P"
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /windows\/meterpreter\/reverse_tcp/
      end

      it "should try to run the check function of an exploit" do
        args = "windows/smb/ms08_067_netapi rhost=0.0.0.1 C"  # Some BS IP so we can fail
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /failed/
      end

      it "should warn my auxiliary module isn't supported by mode 'p' (show payloads)" do
        args = 'auxiliary/scanner/http/http_version p'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /This type of module does not support payloads/
      end

      it "should warn my auxiliary module isn't supported by mode 't' (show targets)" do
        args = 'auxiliary/scanner/http/http_version t'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /This type of module does not support targets/
      end

      it "should warn my exploit module isn't supported by mode 'ac' (show actions)" do
        args = 'windows/browser/ie_cbutton_uaf ac'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /This type of module does not support actions/
      end

      it "should show actions available for module auxiliary/scanner/http/http_put" do
        args = "auxiliary/scanner/http/http_put ac"
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /DELETE/
      end

    end
  end
end