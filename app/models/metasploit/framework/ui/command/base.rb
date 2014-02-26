# @abstract Subclass and define `#run_with_valid` to run when the subclass instance is valid and {#run} is called.  If
#   there are recursive validation errors, {#print_validation_errors} should be overridden and `super` called to print
#   the errors directly on the subclass instance.
class Metasploit::Framework::UI::Command::Base < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] words
  #   Words parsed from command line/console.
  #
  #   @return [Array<String>]
  attr_writer :words

  #
  # Validations
  #

  validate :words_parsable

  #
  # Methods
  #

  # @!method print_error(message=nil)
  #   Print message as an error followed by a new line.
  #
  #   @param message [String]
  #   @return [void]
  #
  # @!method print_good(message=nil)
  #   Print a good message followed by a new line.
  #
  #   @param message [String]
  #   @return [void]
  #
  # @!method print_line(message=nil)
  #   Print `message` followed by a new line.
  #
  #   @param message [String]
  #   @return [void]
  #
  # @!method print_status(message=nil)
  #   Print neutral status.
  #
  #   @param message [String]
  #   @return [void]
  #
  # @!method print_warning(message=nil)
  #   Print warning message.
  #
  #   @param message [String]
  #   @return [void]
  #
  # @!method width
  #    The width of the TTY attached to the {#output}.
  #
  #    @return [80] if the output is not a TTY.
  #    @return [Integer] otherwise.
  delegate :print_error,
           :print_good,
           :print_line,
           :print_status,
           :print_warning,
           :width,
           to: :output

  # Runs the command.  Command is automatically validated.  If it is valid, then {#run_with_valid} will be called,
  # otherwise, if the command is invalid, {#print_validation_errors} is called.
  #
  # @return [void]
  def run
    if valid?
      run_with_valid
    else
      print_validation_errors
    end
  end

  # Words from command line/console that are passed to this command.
  #
  # @return [Array<String>] [] by default
  def words
    @words ||= []
  end

  protected

  # @note `valid?` should be called before using this method to populate `errors`.
  #
  # Prints full error messages directly on this command.
  #
  # @return [void]
  def print_validation_errors
    errors.full_messages.each do |full_message|
      print_error full_message
    end
  end

  private

  def words_parsable
    parse_words

    if @parse_error
      errors[:words] << @parse_error.to_s
    end
  end
end