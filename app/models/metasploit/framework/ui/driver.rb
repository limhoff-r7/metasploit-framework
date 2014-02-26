# -*- coding: binary -*-

# The driver class is an abstract base class that is meant to provide
# a very general set of methods for 'driving' a user interface.
class Metasploit::Framework::UI::Driver < Metasploit::Model::Base
  # Executes the user interface, optionally in an asynchronous fashion.
  #
  # @return [void]
  def run
    raise NotImplementedError
  end

  # Stops executing the user interface.
  #
  # @return [void]
  def stop
  end

  # Cleans up any resources associated with the UI driver.
  #
  # @return [void]
  def cleanup
  end
end
