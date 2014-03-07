# A file saved under {Msf::Framework#pathnames} {Metasploit::Framework::Framework::Pathnames#local} with an accompanying
# `Mdm::Note` in the database.
class Metasploit::Framework::LocalFile < Metasploit::Model::Base
  #
  # CONSTANTS
  #

  # Regexp matching characters that are removed by {normalize}
  ABNORMAL_REGEXP = /[^a-z0-9\.\_\-]+/i
  DEFAULT_EXTENSION = '.bin'
  # Maps {#content_type} to its default {#extension}
  EXTENSION_BY_CONTENT_TYPE = Hash.new(DEFAULT_EXTENSION).tap { |hash|
    hash.merge!(
        'application/pdf' => '.pdf',
        'text/html' => '.html',
        'text/plain' => '.txt',
        'text/xml' => '.xml'
    )
  }

  #
  # Attributes
  #

  # The auxiliary module instance that's trying to write this local file.
  #
  # @return [Msf::Auxiliary::Report, #report_note]
  attr_accessor :auxiliary_instance

  # @!attribute [rw] content_type
  #   The Content-Type of the file, e.g. "text/plain".
  #
  #   @return [String]
  attr_accessor :content_type

  # @!attribute [rw] content
  #   Content to write to the file.
  #
  #   @return [String]
  attr_accessor :content

  # @!attribute [rw] filename
  #   The name of the file under {Metasploit::Framework::Framework::Pathnames#local}.
  #
  #   @return [String]
  attr_writer :filename

  # @!attribute [rw] type_prefix
  #   Dot-separated prefix for `Mdm::Note#type` before `'.localpath'`
  #
  #   @return [String]
  attr_accessor :type_prefix

  #
  # Validations
  #

  validates :auxiliary_instance,
            presence: true
  validates :content,
            presence: true
  validates :type_prefix,
            presence: true

  #
  # Methods
  #

  def filename
    @filename ||= content_type || "local_#{Time.now.utc.to_i}"
  end

  def self.normalize(string)
    string.gsub(ABNORMAL_REGEXP, '')
  end

  def pathname
    @pathname ||= auxiliary_instance.framework.pathnames.local.join(normalized_filename)
  end

  def write
    pathname.parent.mkpath

    pathname.open('wb') { |f|
      f.write(content)
    }

    auxiliary_instance.report_note(
        data: pathname.to_path,
        type: type
    )
  end

  private

  # {#filename} without {#extension}.
  #
  # @return [String]
  def basename
    File.basename(filename, extension)
  end

  def content_type_extension
    EXTENSION_BY_CONTENT_TYPE[content_type]
  end

  def extension
    unless instance_variable_defined? :@extension
      extension = File.extname(filename)

      if extension.blank?
        extension = content_type_extension
      end

      @extension = extension
    end

    @extension
  end

  def normalized_filename
    unless @normalize_filename
      normalized_basename = self.class.normalize(basename)

      @normalize_filename = "#{normalized_basename}#{extension}"
    end

    @normalize_filename
  end

  def normalized_type_prefix
    @normalized_type_prefix ||= self.class.normalize(type_prefix)
  end

  def type
    @type ||= "#{normalized_type_prefix}.localpath"
  end
end