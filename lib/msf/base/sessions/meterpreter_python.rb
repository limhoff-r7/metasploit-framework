# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_Python_Python < Msf::Sessions::Meterpreter
  def supports_ssl?
    false
  end
  def supports_zlib?
    false
  end
  def initialize(rstream, opts={})
    super

    self.architecture_abbreviation = 'Python'
    self.binary_suffix = 'py'
    self.platform = 'python/python'
    self.platform_fully_qualified_name = 'Python'
  end
end

end
end

