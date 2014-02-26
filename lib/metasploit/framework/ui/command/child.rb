module Metasploit::Framework::UI::Command::Child
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
    undef_method :words=
  end

  #
  # Attributes
  #

  # @!attribute [rw] parent
  #   The parent command of which this command is a subcommand.
  #
  #   @return [Metasploit::Framework::UI::Console::Command::Parent]
  attr_accessor :parent

  #
  # Methods
  #

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

  private

  def parse_words
    # Do nothing.  Words are parsed by {#parent}.
  end
end