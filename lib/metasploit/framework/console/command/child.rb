# A command that is a subcommand for a {Metasploit::Framework::Console::Command::Parent}.
module Metasploit::Framework::Console::Command::Child
  extend ActiveSupport::Concern

  included do
    include ActiveModel::Validations

    #
    # Validations
    #

    validates :parent,
              presence: true

    # Undefined writers as they won't be read back out by the readers because those delegate to #parent.  Writers
    # aren't delegated to #parent because it needs to be clear that the #parent is responsible for parsing the words
    undef_method :partial_word=
    undef_method :words=
  end

  #
  # Attributes
  #

  # @!attribute [rw] parent
  #   The parent command of which this command is a subcommand.
  #
  #   @return [Metasploit::Framework::Console::Command::Parent]
  attr_accessor :parent

  #
  # Methods
  #

  def option_parser
    if parent
      parent.option_parser
    else
      super
    end
  end

  delegate :dispatcher,
           :partial_word,
           # must allow nil so that parent can be validated
           allow_nil: true,
           to: :parent

  # Words from {#parent}.
  #
  # @return [Array<String>] from {#parent}
  # @return [[]] if {#parent} is nil
  def words
    unless parent.nil?
      parent.words
    else
      []
    end
  end
end