# @abstract Subclass and define `#run_with_valid` to run when the subclass instance is valid and {#run} is called.  If
#   there are recursive validation errors, {#print_validation_errors} should be overriden and `super` called to print
#   the errors directly on the subclass instance.
#
# A command used in `msfconsole`.
class Metasploit::Framework::Command::Base < Metasploit::Model::Base
  include Metasploit::Framework::Command::TabCompletion

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
  delegate :print_line,
           :print_error,
           :width,
           to: :dispatcher

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
end