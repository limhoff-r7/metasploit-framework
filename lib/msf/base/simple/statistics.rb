# -*- coding: binary -*-
module Msf
module Simple

###
#
# This class provides an interface to various statistics about the
# framework instance.
#
###
class Statistics
  include Msf::Framework::Offspring

  #
  # Initializes the framework statistics.
  #
  def initialize(framework)
    self.framework = framework
  end

  Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE.each do |module_type, directory|
    define_method("num_#{directory}") do
      Mdm::Module::Class.where(module_type: module_type).count
    end
  end
end

end
end
