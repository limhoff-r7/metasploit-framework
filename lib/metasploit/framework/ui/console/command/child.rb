# A command that is a subcommand for a {Metasploit::Framework::UI::Console::Command::Parent}.
module Metasploit::Framework::UI::Console::Command::Child
  extend ActiveSupport::Concern

  include Metasploit::Framework::UI::Command::Child

  included do
    # Undefined writers as they won't be read back out by the readers because those delegate to #parent.  Writers
    # aren't delegated to #parent because it needs to be clear that the #parent is responsible for parsing the words
    undef_method :partial_word=
  end

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
end