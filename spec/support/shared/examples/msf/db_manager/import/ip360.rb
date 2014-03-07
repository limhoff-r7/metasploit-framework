shared_examples_for 'Msf::DBManager::Import::IP360' do
  context '#import_ip360_aspl_xml' do
    def import_ip360_aspl_xml(&block)
      db_manager.import_ip360_aspl_xml(options, &block)
    end

    let(:options) do
      {
          data: data
      }
    end

    context "with '<ontology'" do
      let(:data) do
        '<ontology/>'
      end

      it 'creates ncircle directory' do
        import_ip360_aspl_xml { }

        expect(db_manager.framework.pathnames.data.join('ncircle')).to be_directory
      end

      it 'writes ip360.aspl file' do
        import_ip360_aspl_xml { }
        pathname = db_manager.framework.pathnames.data.join('ncircle', 'ip360.aspl')

        expect(pathname.read).to eq(data)
      end

      it 'yields notice that IP360 ASPL database was saved' do
        expect { |b|
          import_ip360_aspl_xml(&b)
        }.to yield_with_args(
                 :notice,
                 "Saved the IP360 ASPL database to #{db_manager.framework.pathnames.data.join('ncircle')}..."
             )
      end
    end

    context "without '<ontology'" do
      let(:data) do
        'not an aspl file'
      end

      specify {
        expect {
          import_ip360_aspl_xml { }
        }.to raise_error(Msf::DBImportError)
      }
    end
  end
end