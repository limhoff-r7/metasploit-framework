require 'spec_helper'

describe Metasploit::Framework::LocalFile do
  include_context 'Msf::Simple::Framework'

  subject(:local_file) do
    described_class.new(
        auxiliary_instance: auxiliary_instance,
        filename: filename,
        content: content,
        content_type: content_type,
        type_prefix: type_prefix
    )
  end

  let(:auxiliary_instance) do
    auxiliary_class.new(framework: framework)
  end

  let(:auxiliary_class) do
    Class.new(Msf::Auxiliary) do
      include Msf::Auxiliary::Report
    end
  end

  let(:filename) do
    'local_file.txt'
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

  context 'CONSTANTS' do
    context 'ABNORMAL_REGEXP' do
      subject(:abnormal_regexp) do
        described_class::ABNORMAL_REGEXP
      end

      it 'removes spaces' do
        expect("with spaces".gsub(abnormal_regexp, '')).not_to include(' ')
      end
    end

    context 'DEFAULT_EXTENSION' do
      subject(:default_extension) do
        described_class::DEFAULT_EXTENSION
      end

      it { should == '.bin' }
    end

    context 'EXTENSION_BY_CONTENT_TYPE' do
      subject(:extension_by_content_type) do
        described_class::EXTENSION_BY_CONTENT_TYPE
      end

      it 'defaults to DEFAULT_EXTENSION' do
        expect(extension_by_content_type[nil]).to eq(described_class::DEFAULT_EXTENSION)
      end

      it 'has a . before all extensions so they can be concatenated to #basename' do
        expect(
            extension_by_content_type.values.all? { |extension|
              extension.start_with? '.'
            }
        ).to be_true
      end

      its(['application/pdf']) { should == '.pdf' }
      its(['text/html']) { should == '.html' }
      its(['text/plain']) { should == '.txt' }
      its(['text/xml']) { should == '.xml' }
    end
  end

  context 'validations' do
    it { should validate_presence_of :auxiliary_instance }
    it { should validate_presence_of :content }
    it { should validate_presence_of :type_prefix }
  end

  context '#basename' do
    subject(:basename) do
      local_file.send(:basename)
    end

    let(:expected_basename) do
      'basename'
    end

    let(:filename) do
      "#{expected_basename}#{extension}"
    end

    context 'with #extension' do
      let(:extension) do
        '.ext'
      end

      it 'strips #extension' do
        expect(basename).to eq(expected_basename)
      end
    end

    context 'without #extension' do
      let(:extension) do
        nil
      end

      it 'returns #filename' do
        expect(basename).to eq(filename)
      end
    end
  end

  context '#content_type_extension' do
    subject(:content_type_extension) do
      local_file.send(:content_type_extension)
    end

    context '#content_type' do
      context 'with application/pdf' do
        let(:content_type) do
          'application/pdf'
        end

        it { should == '.pdf' }
      end

      context 'with text/html' do
        let(:content_type) do
          'text/html'
        end

        it { should == '.html' }
      end

      context 'with text/plain' do
        let(:content_type) do
          'text/plain'
        end

        it { should == '.txt' }
      end

      context 'with text/xml' do
        let(:content_type) do
          'text/xml'
        end

        it { should == '.xml' }
      end

      context 'with unknown' do
        let(:content_type) do
          'unknown/content+type'
        end

        it { should == '.bin' }
      end
    end
  end

  context '#extension' do
    subject(:extension) do
      local_file.send(:extension)
    end

    context 'with #filename extension' do
      let(:expected_extension) do
        '.extension'
      end

      let(:filename) do
        "basename#{expected_extension}"
      end

      it 'is extension on #filename' do
        expect(extension).to eq(expected_extension)
      end
    end

    context 'without #filename extension' do
      let(:filename) do
        'without_extension'
      end

      it 'uses #content_type_extension' do
        expect(extension).to eq(local_file.send(:content_type_extension))
      end
    end
  end

  context '#filename' do
    subject(:actual_filename) do
      local_file.filename
    end

    context 'with set' do
      let(:filename) do
        'set_filename'
      end

      it 'uses set value' do
        expect(actual_filename).to eq(filename)
      end
    end

    context 'without set' do
      let(:filename) do
        nil
      end

      context 'with #content_type' do
        it 'uses content_type' do
          expect(actual_filename).to eq(content_type)
        end
      end

      context 'without #content_type' do
        let(:content_type) do
          nil
        end

        it "uses local_<timestamp>" do
          expect(actual_filename).to match /local_\d+/
        end
      end
    end
  end

  context 'normalize' do
    subject(:normalize) do
      described_class.normalize(abnormal)
    end

    let(:abnormal) do
      'abnormal string'
    end

    it 'globally removes abnormal characters' do
      expect(abnormal).to receive(:gsub).with(described_class::ABNORMAL_REGEXP, '')

      normalize
    end

    it 'returns a different string' do
      expect(normalize).not_to equal(abnormal)
    end
  end

  context '#normalized_filename' do
    subject(:normalized_filename) do
      local_file.send(:normalized_filename)
    end

    let(:abnormal_basename) do
      'Abnormal+Basename'
    end

    let(:extension) do
      '.extension'
    end

    let(:filename) do
      "#{abnormal_basename}#{extension}"
    end

    it 'normalizes #basename' do
      expect(normalized_filename).to include(described_class.normalize(abnormal_basename))
    end

    it 'appends #extension' do
      expect(normalized_filename).to end_with(extension)
    end
  end

  context '#normalized_type_prefix' do
    subject(:normalized_type_prefix) do
      local_file.send(:normalized_type_prefix)
    end

    let(:type_prefix) do
      'abnormal type prefix'
    end

    it 'normalizes #type_prefix' do
      expect(normalized_type_prefix).to eq('abnormaltypeprefix')
    end
  end

  context '#pathname' do
    subject(:pathname) do
      local_file.pathname
    end

    it 'should be #normalize_filename under frameork local directory' do
      expect(pathname).to eq(framework.pathnames.local.join(local_file.send(:normalized_filename)))
    end
  end

  context '#type' do
    subject(:type) do
      local_file.send(:type)
    end

    it "appends '.localpath' to #normalized_type_prefix" do
      expect(type).to eq("#{local_file.send(:normalized_type_prefix)}.localpath")
    end
  end

  context '#write' do
    subject(:write) do
      local_file.write
    end

    context 'with framework local directory' do
      it 'writes #content to #pathname' do
        write

        expect(local_file.pathname.read).to eq(content)
      end

      it 'reports note' do
        expect(auxiliary_instance).to receive(:report_note).with(
                                          hash_including(
                                              data: local_file.pathname.to_path,
                                              type: local_file.send(:type)
                                          )
                                      )

        write
      end
    end

    context 'without framework local directory' do
      before(:each) do
        framework.pathnames.local.rmdir
      end

      it 'creates directory' do
        expect {
          write
        }.to change(framework.pathnames.local, :exist?).to(true)
      end
    end
  end
end