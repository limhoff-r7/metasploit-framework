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
class Meterpreter_x64_Win < Msf::Sessions::Meterpreter
  def initialize(rstream, opts={})
    super

    self.architecture_abbreviation = 'x86_64'
    self.binary_suffix = 'x64.dll'
    self.platform = 'x64/win64'
    self.platform_fully_qualified_name = 'Windows'
  end

  def lookup_error(code)
    Msf::WindowsError.description(code)
  end
end

end
end
