shared_examples_for 'Msf::Session::Scriptable' do
  context '#execute_script' do
    subject(:execute_script) do
      base_instance.execute_script(script_name, *arguments)
    end

    let(:arguments) do
      arguments_hash.collect { |key, value|
        "#{key}=#{value}"
      }
    end

    let(:arguments_hash) do
      {
          'key1' => 'value1',
          'key2' => 'value2'
      }
    end

    context 'with post Mdm::Module::Class#full_name' do
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

      let(:script_name) do
        cache_post_class.full_name
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

      context 'with Msf::Module' do
        #
        # lets
        #

        let(:post_instance) do
          framework.modules.create_from_module_class(cache_post_class)
        end

        #
        # Callbacks
        #

        before(:each) do
          # rig it to return its normal value, but allow access to returned value for expectations on the return value
          expect(framework.modules).to receive(:create_from_module_class).and_return(post_instance)
        end

        it 'calls #run_simple on module' do
          expect(post_instance).to receive(:run_simple)

          execute_script
        end

        it 'passes current session id to run' do
          expect(post_instance).to receive(:run_simple) { |hash|
            options = hash['Options']

            expect(options).to be_a Hash

            expect(options['SESSION']).to eq(base_instance.sid)
          }

          execute_script
        end

        it 'passes arguments as options' do
          expect(post_instance).to receive(:run_simple) { |hash|
            options = hash['Options']

            expect(options).to be_a Hash

            arguments_hash.each do |key, value|
              expect(options[key]).to eq(value)
            end
          }

          execute_script
        end

        it 'passes I/O to run' do
          expect(post_instance).to receive(:run_simple) { |hash|
            expect(hash['LocalInput']).to eq(base_instance.user_input)
            expect(hash['LocalOutput']).to eq(base_instance.user_output)
          }

          execute_script
        end
      end

      context 'without Msf::Module' do
        include_context 'output'

        before(:each) do
          expect(framework.modules).to receive(:create_from_module_class).and_return(nil)
        end

        it 'print errors that module was found, but could not be instantiated' do
          expect(output).to include("#{script_name} is a post module full name, but it could not be instantiated.")
        end

        it 'tells user to consult framework.log' do
          expect(output).to include(framework.pathnames.logs.join('framework.log').to_s)
        end

        it 'returns true' do
          Kernel.quietly {
            expect(execute_script).to be_true
          }
        end
      end
    end

    context 'without post Mdm::Module::Class#full_name' do
      context 'with existent script' do
        #
        # lets
        #

        let(:pathname) do
          framework.pathnames.scripts.join(base_class.type, script_name)
        end

        let(:script_name) do
          'existent.rb'
        end

        #
        # Callbacks
        #

        before(:each) do
          pathname.parent.mkpath

          pathname.open('wb') do |f|
            f.puts '# A script'
          end
        end

        before(:each) do
          allow(base_instance).to receive(:execute_file)
        end

        it 'fires event' do
          expect(framework.events).to receive(:on_session_script_run).with(base_instance, pathname)

          execute_script
        end

        it 'executes file' do
          expect(base_instance).to receive(:execute_file).with(pathname, arguments)

          execute_script
        end
      end

      context 'without existent script' do
        include_context 'output'

        let(:script_name) do
          'non_existent.rb'
        end

        it 'prints error' do
          expect(output).to match /could not be found.*#{script_name}/
        end

        it 'returns true' do
          Kernel.quietly {
            expect(execute_script).to be_true
          }
        end
      end
    end
  end

  context 'script_pathnames' do
    def script_pathnames(&block)
      base_class.script_pathnames(options, &block)
    end

    let(:options) do
      {}
    end

    context 'without :basename' do
      it 'raises KeyError' do
        expect {
          script_pathnames
        }.to raise_error(KeyError)
      end
    end

    context 'with :basename' do
      let(:basename) do
        'script_base_name'
      end

      let(:options) do
        {
            basename: basename
        }
      end

      context 'with block' do
        context 'with :framework' do
          let(:options) do
            super().merge(
                framework: framework
            )
          end

          it 'calls scripts_pathnames with :framework' do
            expect(base_class).to receive(:scripts_pathnames).with(
                                      hash_including(framework: framework)
                                  )

            script_pathnames { }
          end

          it 'yields <basename> before <basename>.rb' do
            indexed_pathnames_by_parent = script_pathnames.each_with_index.group_by { |(pathname, index)|
              pathname.parent
            }

            indexed_pathnames_by_parent.each do |_, indexed_pathnames|
              sorted_pathnames = indexed_pathnames.sort_by { |_, index|
                index
              }.collect { |pathname, _|
                pathname
              }

              expect(sorted_pathnames.first.extname).to eq('')
              expect(sorted_pathnames.last.extname).to eq('.rb')
            end
          end
        end

        context 'without :framework' do
          it 'yields scripts from installation only' do
            expect(
                script_pathnames.all? { |pathname|
                  !pathname.relative_path_from(Metasploit::Framework.pathnames.scripts).to_s.include? '..'
                }
            ).to be_true
          end

          it 'yields <basename> before <basename>.rb' do
            type_pathname = Metasploit::Framework.pathnames.scripts.join(base_class.type)

            expect { |b|
              script_pathnames(&b)
            }.to yield_successive_args(
                     type_pathname.join(basename),
                     type_pathname.join("#{basename}.rb")
                 )
          end
        end
      end

      context 'without block' do
        it 'returns an Enumerator' do
          expect(script_pathnames).to be_an(Enumerator)
        end
      end
    end
  end

  context 'scripts_pathnames' do
    def scripts_pathnames(&block)
      base_class.scripts_pathnames(options, &block)
    end

    let(:options) do
      {}
    end

    context 'with :framework' do
      let(:options) do
        {
            framework: framework
        }
      end

      context 'with block' do
        it 'yields scripts for :framework before scripts for installation' do
          expect { |b|
            scripts_pathnames(&b)
          }.to yield_successive_args(
                   framework.pathnames.scripts.join(base_class.type),
                   Metasploit::Framework.pathnames.scripts.join(base_class.type)
               )
        end
      end

      context 'without block' do
        it 'is an Enumerator' do
          expect(scripts_pathnames).to be_an(Enumerator)
        end
      end
    end

    context 'without :framework' do
      it 'yields installation scripts pathname only' do
        expect { |b|
          scripts_pathnames(&b)
        }.to yield_with_args(Metasploit::Framework.pathnames.scripts.join(base_class.type))
      end
    end
  end

  context 'find_script_pathname' do
    subject(:find_script_pathname) do
      base_class.find_script_pathname(options)
    end

    let(:options) do
      {
          basename: basename,
          framework: framework
      }
    end

    context 'with non-existent script' do
      let(:basename) do
        'non-existent'
      end

      it { should be_nil }
    end

    context 'with script under installed scripts' do
      let(:basename) do
        'migrate.rb'
      end

      context 'with script under framework scripts' do
        #
        # lets
        #

        let(:pathname) do
          framework.pathnames.scripts.join(base_class.type).join(basename)
        end

        #
        # Callbacks
        #

        before(:each) do
          pathname.parent.mkpath

          pathname.open('w') { |f|
            f.puts '# A script'
          }
        end

        it 'favors script under framework scripts' do
          expect(find_script_pathname).to eq(pathname)
        end
      end

      context 'without script under framework scripts' do
        it 'returns pathname from installed scripts' do
          expect(find_script_pathname).to eq(Metasploit::Framework.pathnames.scripts.join(base_class.type, basename))
        end
      end
    end
  end
end