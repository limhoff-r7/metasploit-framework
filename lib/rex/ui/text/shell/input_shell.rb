###
#
# This module is meant to be mixed into an input medium class instance as a
# means of extending it to display a prompt before each call to gets.
#
###
module Rex::Ui::Text::Shell::InputShell
  attr_accessor :prompt, :output

  def pgets()
    output.print(prompt)
    output.flush

    output.prompting
    buf = gets
    output.prompting(false)

    buf
  end
end