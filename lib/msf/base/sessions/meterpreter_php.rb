# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_Php_Php < Msf::Sessions::Meterpreter
  def supports_ssl?
    false
  end
  def supports_zlib?
    false
  end
  def initialize(rstream, opts={})
    super

    self.architecture_abbreviation = 'PHP'
    self.binary_suffix = 'php'
    self.platform = 'php/php'
    self.platform_fully_qualified_name = 'PHP'
  end
end

end
end

