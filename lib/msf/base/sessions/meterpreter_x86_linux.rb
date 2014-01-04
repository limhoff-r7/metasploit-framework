# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x86_Linux < Msf::Sessions::Meterpreter
  def initialize(rstream, opts={})
    super

    self.architecture_abbreviation = 'x86'
    self.binary_suffix = 'lso'
    self.platform = 'x86/linux'
    self.platform_fully_qualified_name = 'Linux'
  end
end

end
end

