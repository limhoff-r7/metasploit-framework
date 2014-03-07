shared_examples_for 'Msf::Auxiliary::JohnTheRipper' do
  it_should_behave_like 'Msf::Auxiliary::Report'

  context '#john_base_path' do
    #
    # Shared examples
    #

    shared_examples_for "without data_store['JOHN_BASE']" do
      #
      # Shared examples
      #

      shared_examples_for "without data_store['JOHN_PATH']" do
        it 'returns installation path' do
          expect(john_base_path).to eq(Metasploit::Framework.pathnames.data.join('john').to_path)
        end
      end

      context "with data_store['JOHN_PATH']" do
        let(:john_parent_pathname) do
          Metasploit::Model::Spec.temporary_pathname.join('john')
        end

        let(:john_pathname) do
          john_parent_pathname.join('path')
        end

        #
        # Callbacks
        #

        before(:each) do
          auxiliary_instance.data_store['JOHN_PATH'] = john_pathname.to_path
        end

        context 'with file' do
          before(:each) do
            john_parent_pathname.mkpath

            john_pathname.open('wb') { |f|
              f.puts '# John The Ripper'
            }
          end

          it 'return parent directory' do
            expect(john_base_path).to eq(john_parent_pathname.to_path)
          end
        end

        context 'without file' do
          it_should_behave_like "without data_store['JOHN_PATH']"
        end
      end

      it_should_behave_like "without data_store['JOHN_PATH']"
    end

    subject(:john_base_path) do
      auxiliary_instance.john_base_path
    end

    context "with data_store['JOHN_BASE']" do
      let(:john_base_pathname) do
        Metasploit::Model::Spec.temporary_pathname.join('john')
      end

      before(:each) do
        auxiliary_instance.data_store['JOHN_BASE'] = john_base_pathname.to_path
      end

      context 'with directory' do
        before(:each) do
          john_base_pathname.mkpath
        end

        it "returns data_store['JOHN_BASE']" do
          expect(john_base_path).to eq(john_base_pathname.to_path)
        end
      end

      context 'without directory' do
        it_should_behave_like "without data_store['JOHN_BASE']"
      end
    end

    it_should_behave_like "without data_store['JOHN_BASE']"
  end

  context '#john_pot_pathname' do
    subject(:john_pot_pathname) do
      auxiliary_instance.john_pot_pathname
    end

    it 'should be under framework root' do
      expect(john_pot_pathname).to eq(framework.pathnames.root.join('john.pot'))
    end
  end
end