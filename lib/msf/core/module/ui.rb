require 'msf/core/module/data_store'
require 'rex/ui/subscriber'

module Msf::Module::UI
  include Msf::Module::DataStore

  require 'msf/core/module/ui/verbose'
  include Msf::Module::UI::Verbose

  # Modules can subscribe to a user-interface, and as such they include the
  # UI subscriber module.  This provides methods like print, print_line, etc.
  # User interfaces are designed to be medium independent, and as such the
  # user interface subscribes are designed to provide a flexible way of
  # interacting with the user, n stuff.
  include Rex::Ui::Subscriber

  #
  # Methods
  #

  def print_good(msg='')
    super(print_prefix + msg)
  end

  def print_error(msg='')
    super(print_prefix + msg)
  end

  def print_line(msg='')
    super(print_line_prefix + msg)
  end

  def print_status(msg='')
    super(print_prefix + msg)
  end

  def print_warning(msg='')
    super(print_prefix + msg)
  end

  private

  def print_line_prefix
    data_store['CustomPrintPrefix'] || framework.data_store['CustomPrintPrefix'] || ''
  end

  def print_prefix
    if (data_store['TimestampOutput'] =~ /^(t|y|1)/i) || (
      framework && framework.data_store['TimestampOutput'] =~ /^(t|y|1)/i
    )
      prefix = "[#{Time.now.strftime("%Y.%m.%d-%H:%M:%S")}] "

      xn ||= data_store['ExploitNumber']
      xn ||= framework.data_store['ExploitNumber']
      if xn.is_a?(Fixnum)
        prefix << "[%04d] " % xn
      end

      return prefix
    else
      return ''
    end
  end
end