# Adds support for declaring {ClassMethods#subcommands} on this command.
module Metasploit::Framework::Console::Command::Parent
  extend ActiveSupport::Concern

  include Metasploit::Framework::Command::Parent

  #
  # Instance Methods
  #

  def blank_tab_completions
    completions = []

    # if there are no words, then the user can either ask for help or use the subcommand as usual
    if words.empty?
      completions += [
          '-h',
          '--help'
      ]
    end

    completions += subcommand.blank_tab_completions

    completions
  end

  def option_parser
    unless instance_variable_defined? :@option_parser
      super

      @option_parser.on_tail('-h', '--help', 'Show this help') do
        self.subcommand_name = :help
      end
    end

    @option_parser
  end

  delegate :partial_tab_completions,
           to: :subcommand
end