# @abstract Subclass and define `#run_with_valid` to run when the subclass instance is valid and {#run} is called.  If
#   there are recursive validation errors, {#print_validation_errors} should be overriden and `super` called to print
#   the errors directly on the subclass instance.
#
# A command used in `msfconsole`.
class Metasploit::Framework::Console::Command::Base < Metasploit::Framework::Command::Base
  include Metasploit::Framework::Console::Command::TabCompletion

  #
  # Attributes
  #

  # @!attribute [rw] dispatcher
  #   Command dispatcher
  #
  #   @return [Msf::Ui::Console::CommandDispatcher]
  attr_accessor :dispatcher

  #
  # Validations
  #

  validates :dispatcher,
            presence: true

  #
  # Methods
  #

  class << self
    # The name of this command as called from the {#dispatcher}.
    #
    # @return [String]
    def command_name
      name.demodulize.underscore
    end

    attr_accessor :description

    # Declares {#words} parsing routine.
    #
    # @yield [parsable_words] Body of #parse_words method specific to this class.
    # @yieldparam parsable_words [Array<String>] A duplicate of {#words} that can be safely modified by
    #   `OptionParser#parse!` without changing {#words}.
    def parse_words(&block)
      @parse_words_block = block
    end

    attr_writer :parse_words_block

    def parse_words_block
      @parse_words_block ||= ->(parsable_words) {
        option_parser.parse!(parsable_words)
      }
    end
  end

  def option_parser
    @option_parser ||= OptionParser.new { |option_parser|
      option_parser.banner = "Usage: #{self.class.command_name} [options]"
    }
  end

  # @!method print_line(message=nil)
  #   Print `messages` followed by a new line.
  #
  #   @return [void]
  #
  # @!method print_error(message=nil)
  #   Print message as an error (prefixed by red '[-]') followed by a new line.
  #
  #   @return [void]
  #
  # @!method width
  #    The width of the TTY attached to the {#dispatcher}'s output.
  #
  #    @return [80] if the output is not a TTY.
  #    @return [Integer] otherwise.
  delegate :print_error,
           :print_good,
           :print_line,
           :print_status,
           :print_warning,
           :width,
           to: :dispatcher

  private

  # Parses {#words} using {parse_words_block}.  `OptionParser::ParseError` are stored to `@parse_error` and converted to
  # a validation error by {#words_parsable}.
  #
  # @return [void]
  def parse_words
    unless @words_parsed
      # have to dup because OptionParse#parse! will modify the Array.
      parsable_words = words.dup

      begin
        instance_exec(parsable_words, &self.class.parse_words_block)
      rescue OptionParser::ParseError => error
        @parse_error = error
      end

      @words_parsed = true
    end
  end
end