# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_Java_Java < Msf::Sessions::Meterpreter
  def supports_ssl?
    false
  end
  def supports_zlib?
    false
  end
  def initialize(rstream, opts={})
    super

    self.architecture_abbreviation = 'Java'
    self.binary_suffix = 'jar'
    self.platform = 'java/java'
    self.platform_fully_qualified_name = 'Java'
  end
end

end
end

