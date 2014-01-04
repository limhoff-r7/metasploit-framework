# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x86_BSD < Msf::Sessions::Meterpreter
  def initialize(rstream, opts={})
    super

    self.architecture_abbreviation = 'BSD'
    self.binary_suffix = 'bso'
    self.platform = 'x86/bsd'
    self.platform_fully_qualified_name = 'x86'
  end
end

end
end

