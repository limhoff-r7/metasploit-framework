require 'spec_helper'

require 'file/find'

describe Metasploit::Framework::Module::Cache, :cache do
  subject(:module_cache) do
    described_class.new
  end

  context 'CONSTANTS' do
    context 'MODULE_CLASS_LOAD_CLASS_BY_PAYLOAD_TYPE_BY_MODULE_TYPE' do
      include_context 'database cleaner'

      subject(:module_class_load_class) do
        described_class::MODULE_CLASS_LOAD_CLASS_BY_PAYLOAD_TYPE_BY_MODULE_TYPE[module_class.module_type][module_class.payload_type]
      end

      context 'module_type' do
        let(:module_class) do
          FactoryGirl.create(
              :mdm_module_class,
              module_type: module_type
          )
        end

        context 'with auxiliary' do
          let(:module_type) do
            'auxiliary'
          end

          it { should == Metasploit::Framework::Module::Class::Load::NonPayload }
        end

        context 'with encoder' do
          let(:module_type) do
            'encoder'
          end

          it { should == Metasploit::Framework::Module::Class::Load::NonPayload }
        end

        context 'with exploit' do
          let(:module_type) do
            'encoder'
          end

          it { should == Metasploit::Framework::Module::Class::Load::NonPayload }
        end

        context 'with nop' do
          let(:module_type) do
            'encoder'
          end

          it { should == Metasploit::Framework::Module::Class::Load::NonPayload }
        end

        context 'with payload' do
          let(:module_type) do
            'payload'
          end

          context 'payload_type' do
            let(:module_class) do
              FactoryGirl.create(
                  :mdm_module_class,
                  module_type: module_type,
                  payload_type: payload_type
              )
            end

            context 'with single' do
              let(:payload_type) do
                'single'
              end

              it { should == Metasploit::Framework::Module::Class::Load::Payload::Single }
            end

            context 'with staged' do
              let(:payload_type) do
                'staged'
              end

              it { should == Metasploit::Framework::Module::Class::Load::Payload::Staged }
            end
          end
        end

        context 'with post' do
          let(:module_type) do
            'post'
          end

          it { should == Metasploit::Framework::Module::Class::Load::NonPayload }
        end
      end
    end
  end

  context 'factories' do
    context 'metasploit_framework_module_cache' do
      include_context 'Msf::Logging'

      subject(:metasploit_framework_module_cache) do
        FactoryGirl.build(:metasploit_framework_module_cache)
      end

      it { should be_valid }
    end
  end

  context 'validations' do
    it { should validate_presence_of :module_manager }
  end

  context '#framework' do
    subject(:framework) do
      module_cache.framework
    end

    let(:expected_framework) do
      double('Msf::Framework')
    end

    let(:module_manager) do
      double('Msf::ModuleManager', framework: expected_framework)
    end

    before(:each) do
      module_cache.stub(module_manager: module_manager)
    end

    it 'should delegate to #module_manager' do
      framework.should == module_manager.framework
    end
  end

  context '#metasploit_class' do
    include_context 'database cleaner'
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    subject(:metasploit_class) do
      module_cache.metasploit_class(module_class)
    end

    context 'module_type' do
      let(:module_class) do
        # have to build instead of create since invalid module_type and payload_types are being tested
        FactoryGirl.build(
            :mdm_module_class,
            module_type: module_type,
            payload_type: payload_type
        )
      end

      before(:each) do
        # validate to trigger derivations
        module_class.valid?
      end

      context 'with valid' do
        Metasploit::Model::Module::Type::NON_PAYLOAD.each do |module_type|
          it_should_behave_like 'Metasploit::Framework::Module::Cache#metasploit_class load non-payload',
                                module_type: module_type
        end

        context 'with payload' do
          let(:module_type) do
            'payload'
          end

          context 'payload_type' do
            context 'with single' do
              let(:payload_type) do
                'single'
              end

              it_should_behave_like 'Metasploit::Framework::Module::Cache#metasploit_class load',
                                    module_class_load_class: Metasploit::Framework::Module::Class::Load::Payload::Single
            end

            context 'with staged' do
              let(:payload_type) do
                'staged'
              end

              it_should_behave_like 'Metasploit::Framework::Module::Cache#metasploit_class load',
                                    module_class_load_class: Metasploit::Framework::Module::Class::Load::Payload::Staged
            end

            context 'with nil' do
              let(:payload_type) do
                FactoryGirl.generate :metasploit_model_module_class_payload_type
              end

              before(:each) do
                # set after build or ancestors won't be setup correctly and factory will raise ArgumentError
                module_class.payload_type = nil
              end

              it { should be_nil }
            end
          end
        end
      end

      context 'without valid' do
        let(:module_type) do
          'unknown_module_type'
        end
      end
    end
  end

  context '#path_set' do
    subject(:path_set) do
      module_cache.path_set
    end

    it 'should be memoized' do
      memoized = double('Metasploit::Framework::Module::PathSet::Database')
      module_cache.instance_variable_set :@path_set, memoized

      path_set.should == memoized
    end

    it { should be_a Metasploit::Framework::Module::PathSet::Base }

    it 'should be validated' do
      Metasploit::Framework::Module::PathSet::Base.any_instance.should_receive(:valid!)

      path_set
    end

    context 'cache' do
      subject(:cache) do
        path_set.cache
      end

      it 'should be parent module cache' do
        cache.should == module_cache
      end
    end
  end

  context '#prefetch' do
    context 'with factories' do
      include_context 'database cleaner'
      include_context 'Msf::Logging'

      #
      # lets
      #

      let(:module_cache) do
        FactoryGirl.create(:metasploit_framework_module_cache)
      end

      let(:module_manager) do
        module_cache.module_manager
      end

      let(:path_set) do
        module_cache.path_set
      end

      #
      # let!s
      #

      let!(:module_paths) do
        FactoryGirl.create_list(:mdm_module_path, 3)
      end

      context 'with :only' do
        subject(:prefetch) do
          module_cache.prefetch only: only
        end

        context 'with Metasploit::Model::Module::Path' do
          let(:only) do
            module_paths.sample
          end

          it 'should have Metasploit::Model::Module::Path for :only option' do
            only.should be_a Metasploit::Model::Module::Path
          end

          it 'should ensure that #path_set contains Metasploit::Model::Module::Path' do
            path_set.should_receive(:superset!).with([only])

            prefetch
          end

          it 'should have Metasploit::Framework::Module::Path::Load for Metasploit::Model::Module::Path' do
            Metasploit::Framework::Module::Path::Load.should_receive(:new).with(
                hash_including(
                    module_path: only
                )
            ).and_call_original

            prefetch
          end

          it 'should set Metasploit::Framework::Module::Path::Load#cache' do
            Metasploit::Framework::Module::Path::Load.should_receive(:new).with(
                hash_including(
                    cache: module_cache
                )
            ).and_call_original

            prefetch
          end

          it 'should iterate through Metasploit::Framework::Module::Ancestor::Loads' do
            Metasploit::Framework::Module::Path::Load.any_instance.should_receive(:each_module_ancestor_load)

            prefetch
          end

          it 'should write each Metasploit::Framework::Module::Ancestor::Load to the cache' do
            module_ancestor_loads = 2.times.collect { |n|
              double("Metasploit::Framework::Module::Ancestor::Load #{n}")
            }
            expectation = Metasploit::Framework::Module::Path::Load.any_instance.should_receive(:each_module_ancestor_load)

            module_ancestor_loads.inject(expectation) { |expectation, module_ancestor_load|
              expectation.and_yield(module_ancestor_load)
            }

            module_ancestor_loads.each do |module_ancestor_load|
              module_cache.should_receive(:write_module_ancestor_load).with(module_ancestor_load)
            end

            prefetch
          end
        end

        context 'with Array<Metasploit::Model::Module::Path>' do
          let(:only) do
            module_paths.sample(2)
          end

          it 'should have Array for :only option' do
            only.should be_an Array
          end

          it 'should ensure that #path_set contains all Metasploit::Model::Module::Paths' do
            path_set.should_receive(:superset!).with(only)

            prefetch
          end

          it 'should have Metasploit::Framework::Module::Path::Load for each Metasploit::Model::Module::Path' do
            only.each do |module_path|
              Metasploit::Framework::Module::Path::Load.should_receive(:new).with(
                  hash_including(
                      module_path: module_path
                  )
              ).and_call_original
            end

            prefetch
          end
        end
      end

      context 'without :only' do
        subject(:prefetch) do
          module_cache.prefetch
        end

        it 'should use all Metasploit::Model::Module::Paths in #path_set' do
          path_set.should_receive(:all).and_return([])

          prefetch
        end

        it 'should have Metasploit::Framework::Module::Path::Load for each Metasploit::Model::Module::Path' do
          module_paths.each do |module_path|
            Metasploit::Framework::Module::Path::Load.should_receive(:new).with(
                hash_including(
                    module_path: module_path
                )
            ).and_call_original
          end

          prefetch
        end

        context 'for reload_all msfconsole command' do
          let(:default_changed) do
            false
          end

          it 'should pass :changed' do
            module_paths.each do |_|
              Metasploit::Framework::Module::Path::Load.should_receive(:new).with(
                  hash_including(
                      changed: default_changed
                  )
              ).and_call_original
            end

            prefetch
          end

          it 'should pass a new progress bar to Metasploit::Framework::Module::Path::Load' do
            progress_bars = []

            module_paths.each do |_|
              Metasploit::Framework::Module::Path::Load.should_receive(:new) { |options|
                progress_bar = options[:progress_bar]

                progress_bar.should_not be_nil
                progress_bar.should_not be_in progress_bars

                progress_bars << progress_bar
              }.and_call_original
            end

            prefetch
          end

          context 'with :progress_bar_factory' do
            subject(:prefetch) do
              module_cache.prefetch(progress_bar_factory: progress_bar_factory)
            end

            #
            # lets
            #

            let(:progress_bar_factory) do
              ->{}
            end

            it 'should call factory to produce progress bars for each Metasploit::Framework::Module::Path::Load' do
              module_paths.each_with_index do |module_path, i|
                progress_bar = double("ProgressBar #{i}").as_null_object

                progress_bar_factory.should_receive(:call).and_return(progress_bar)
                Metasploit::Framework::Module::Path::Load.should_receive(:new).with(
                    hash_including(
                        module_path: module_path,
                        progress_bar: progress_bar
                    )
                ).and_call_original
              end

              prefetch
            end
          end

          context 'without :progress_bar_factory' do
            it 'should call #default_progress_bar_factory to produce progress bar for each Metasploit::Framework::Module::Path::Load' do
              module_paths.each_with_index do |module_path, i|
                progress_bar = double("ProgressBar #{i}").as_null_object

                module_cache.should_receive(:default_progress_bar_factory).and_return(progress_bar)
                Metasploit::Framework::Module::Path::Load.should_receive(:new).with(
                    hash_including(
                        module_path: module_path,
                        progress_bar: progress_bar
                    )
                ).and_call_original
              end

              prefetch
            end
          end
        end
      end
    end

    context 'with real module files', :content do
      include_context 'database cleaner', after: :all
      include_context 'Metasploit::Framework::Spec::Constants cleaner', after: :all
      include_context 'Msf::Logging'

      module_path_real_pathname = Metasploit::Framework.root.join('modules')

      before(:all) do
        module_cache = FactoryGirl.create(:metasploit_framework_module_cache)

        module_manager = module_cache.module_manager
        module_manager.should_not be_nil

        framework = module_manager.framework
        framework.should_not be_nil

        @module_path = FactoryGirl.create(
            :mdm_module_path,
            gem: 'metasploit-framework',
            name: 'modules',
            real_path: module_path_real_pathname.to_path
        )

        module_cache.path_set.add(@module_path.real_path, gem: 'metasploit-framework', name: 'modules')
        progress_bar_factory = Metasploit::Framework::Spec::ProgressBar.method(:new)
        module_cache.prefetch(
            only: @module_path,
            # supply progress bars so that travis-ci doesn't think the build is hung while the cache constructs
            progress_bar_factory: progress_bar_factory
        )
      end

      context '#module_type' do
        context 'with payload' do
          context '#payload_type' do
            it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch with payload',
                                  module_classes: :have_exactly,
                                  payload_type: 'single'

            it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch with payload',
                                  module_classes: :have_at_least,
                                  payload_type: 'stage'

            it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch with payload',
                                  module_classes: :have_at_least,
                                  payload_type: 'stager'
          end
        end

        Metasploit::Model::Module::Type::NON_PAYLOAD.each do |module_type|
          it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch with non-payload',
                                module_type: module_type

        end
      end
    end
  end

  context '#write_module_ancestor_load' do
    include_context 'database cleaner'
    include_context 'Metasploit::Framework::Spec::Constants cleaner'
    include_context 'Msf::Logging'

    subject(:write_module_ancestor_load) do
      module_cache.write_module_ancestor_load(module_ancestor_load)
    end

    #
    # lets
    #

    let(:author) do
      FactoryGirl.create(:mdm_author)
    end

    let(:description) do
      FactoryGirl.generate :metasploit_model_module_instance_description
    end

    let(:email_address) do
      FactoryGirl.create(:mdm_email_address)
    end

    let(:formatted_author) do
      msf_module_author = Msf::Module::Author.new
      msf_module_author.email = email_address.full
      msf_module_author.name = author.name

      msf_module_author.to_s
    end

    let(:license) do
      FactoryGirl.generate :metasploit_model_module_instance_license
    end

    let(:module_action_name) do
      FactoryGirl.generate :metasploit_model_module_action_name
    end

    let(:module_ancestor) do
      FactoryGirl.build(
          :mdm_module_ancestor,
          # hard-code type to be non-payload and so that class declaration can be faked
          module_type: 'auxiliary'
      )
    end

    let(:module_ancestor_load) do
      FactoryGirl.build(
          :metasploit_framework_module_ancestor_load,
          module_ancestor: module_ancestor
      )
    end

    let(:module_cache) do
      FactoryGirl.create(:metasploit_framework_module_cache)
    end

    let(:name) do
      FactoryGirl.generate :metasploit_model_module_instance_name
    end

    #
    # callbacks
    #

    before(:each) do
      module_ancestor.valid?

      open(module_ancestor.real_path, 'w') do |f|
        f.puts "require 'msf/core'"
        f.puts ''
        f.puts 'class Metasploit4 < Msf::Auxiliary'
        f.puts '  Rank = ManualRanking'
        f.puts '  '
        f.puts '  def initialize(info={})'
        f.puts '    super('
        f.puts '        update_info('
        f.puts '            info,'
        f.puts "            'Actions' => ["
        f.puts '                ['
        f.puts "                    #{module_action_name.inspect},"
        f.puts '                    {}'
        f.puts '                ]'
        f.puts "            ],"
        f.puts "            'Author' => #{formatted_author.inspect},"
        f.puts "            'Description' => #{description.inspect},"
        f.puts "            'License' => #{license.inspect},"
        f.puts "            'Name' => #{name.inspect},"
        f.puts '        )'
        f.puts '    )'
        f.puts '  end'
        f.puts 'end'
      end
    end

    it 'should not validate uniqueness of module_ancestor_load' do
      ActiveRecord::Validations::UniquenessValidator.should_not_receive(:validate_each).with(module_ancestor_load, anything, anything)

      write_module_ancestor_load
    end

    it 'should validate module_ancestor_load' do
      module_ancestor_load.should_receive(:valid?)

      write_module_ancestor_load
    end

    context 'module_ancestor_load' do
      context 'with valid' do

        it 'should retrieve the Metasploit::Framework::Module::Ancestor::Load#metasploit_module' do
          # stub valid so it can't call metasploit_module
          module_ancestor_load.stub(valid?: true)

          module_ancestor_load.should_receive(:metasploit_module).and_call_original

          write_module_ancestor_load
        end

        it 'should enumerate each metasploit class of the metasploit module so they can be cached' do
          # stub valid so it can't call metasploit_module
          module_ancestor_load.stub(valid?: true)

          metasploit_module = double('MetasploitModule')
          module_ancestor_load.stub(metasploit_module: metasploit_module)

          metasploit_module.should_receive(:each_metasploit_class)

          write_module_ancestor_load
        end

        it 'should cache Module::Class' do
          expect {
            write_module_ancestor_load
          }.to change(Mdm::Module::Class, :count).by(1)
        end


        context 'metasploit_class.new' do
          let(:metasploit_class) do
            metasploit_module.each_metasploit_class.first
          end

          let(:metasploit_module) do
            module_ancestor_load.metasploit_module
          end

          it 'should instantiate metasploit_class' do
            metasploit_class.should_receive(:new).with(
                hash_including(
                    framework: module_cache.framework
                )
            ).and_call_original

            write_module_ancestor_load
          end

          context 'with exception' do
            let(:error) do
              Exception.new("message")
            end

            before(:each) do
              metasploit_class.stub(:new).and_raise(error)
            end

            it 'should log exception' do
              module_cache.should_receive(:elog).with(/#{error.class} #{error}/)

              write_module_ancestor_load
            end

            it { should be_false }
          end

          context 'without exception' do
            context 'metasploit_instance' do
              context 'with valid' do
                it 'should cache Module::Instance' do
                  expect {
                    write_module_ancestor_load
                  }.to change(Mdm::Module::Instance, :count).by(1)
                end

                it { should be_true }
              end

              context 'without valid' do
                before(:each) do
                  metasploit_class.any_instance.should_receive(:valid?).and_return(false)
                end

                it 'should log error' do
                  module_cache.should_receive(:elog)

                  write_module_ancestor_load
                end

                it { should be_false }
              end
            end
          end
        end
      end

      context 'without valid' do
        before(:each) do
          module_ancestor_load.stub(valid?: false)
        end

        it { should be_false }
      end
    end
  end
end