# @abstract Subclass and define `#run_with_valid` to run when the subclass instance is valid and {#run} is called.  If
#   there are recursive validation errors, {#print_validation_errors} should be overridden and `super` called to print
#   the errors directly on the subclass instance.
class Metasploit::Framework::Command::Base < Metasploit::Model::Base
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