shared_examples_for 'Msf::Auxiliary::Report' do
  let(:task) do
    FactoryGirl.create(:mdm_task)
  end

  let(:workspace) do
    FactoryGirl.create(:mdm_workspace)
  end

  it_should_behave_like 'Msf::Auxiliary::Report::Workspace'

  context 'getters' do
    it_should_behave_like 'Msf::Auxiliary::Report.get', :client
    it_should_behave_like 'Msf::Auxiliary::Report.get', :host
  end

  context 'reporters' do
    it_should_behave_like 'Msf::Auxiliary::Report.report', :auth_info
    it_should_behave_like 'Msf::Auxiliary::Report.report', :client
    it_should_behave_like 'Msf::Auxiliary::Report.report', :exploit
    it_should_behave_like 'Msf::Auxiliary::Report.report', :host
    it_should_behave_like 'Msf::Auxiliary::Report.report', :loot
    it_should_behave_like 'Msf::Auxiliary::Report.report', :note
    it_should_behave_like 'Msf::Auxiliary::Report.report', :service
    it_should_behave_like 'Msf::Auxiliary::Report.report', :vuln
    it_should_behave_like 'Msf::Auxiliary::Report.report', :web_form
    it_should_behave_like 'Msf::Auxiliary::Report.report', :web_page
    it_should_behave_like 'Msf::Auxiliary::Report.report', :web_site
    it_should_behave_like 'Msf::Auxiliary::Report.report', :web_vuln
  end

  context '#mytask' do
    subject(:mytask) do
      auxiliary_instance.mytask
    end

    context 'with [:task]' do
      #
      # lets
      #

      let(:module_store_task) do
        # XXX I'm not sure what type is supposed to actually be used in the module_store.
        double('Msf::Module#module_store', record: task)
      end

      #
      # Callbacks
      #

      before(:each) do
        auxiliary_instance[:task] = module_store_task
      end

      it 'should be [:task].record' do
        mytask.should == task
      end
    end

    context 'without [:task]' do
      context 'with @task' do
        before(:each) do
          auxiliary_instance.instance_variable_set :@task, instance_task
        end

        context 'with Mdm::Task' do
          let(:instance_task) do
            task
          end

          it 'should be @task' do
            mytask.should == task
          end
        end

        context 'without Mdm::Task' do
          let(:instance_task) do
            double('Not an Mdm::Task')
          end

          it { should be_nil }
        end
      end

      context 'without @task' do
        it { should be_nil }
      end
    end
  end

  context '#store_cred' do
    it 'should work'
  end

  context '#store_local' do
    subject(:store_local) do
      auxiliary_instance.store_local(type_prefix, content_type, content, filename)
    end

    let(:filename) do
      'local-file-name.txt'
    end

    let(:content) do
      'Content'
    end

    let(:content_type) do
      'application/metasploit-framework'
    end

    let(:type_prefix) do
      'type.prefix'
    end

    it 'creates an Metasploit::Framework::LocalFile' do
      expect(Metasploit::Framework::LocalFile).to receive(:new).with(
                                                      hash_including(
                                                          auxiliary_instance: auxiliary_instance,
                                                          filename: filename,
                                                          content: content,
                                                          content_type: content_type,
                                                          type_prefix: type_prefix
                                                      )
                                                  ).and_call_original

      store_local
    end

    it 'writes content to file on disk' do
      path = store_local

      File.open(path) { |f|
        expect(f.read).to eq(content)
      }
    end

    it 'returns path to local file' do
      expect(store_local).to eq(framework.pathnames.local.join(filename).to_path)
    end
  end

  context '#store_loot' do
    it 'should work'
  end
end