# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'
require 'msf/windows_error'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x86_Win < Msf::Sessions::Meterpreter
  def initialize(rstream,opts={})
    super

    self.binary_suffix = 'dll'
    self.architecture_abbreviation = 'x86'
    self.platform = 'x86/win32'
    self.platform_fully_qualified_name = 'Windows'
  end

  def lookup_error(code)
    Msf::WindowsError.description(code)
  end
end

end
end
