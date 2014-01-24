require 'msf/core/module/data_store'
require 'msf/core/module/options'
require 'msf/core/option_container'

module Msf::Module::Workspace
  include Msf::Module::DataStore
  include Msf::Module::Options

  def initialize(info={})
    super

    register_advanced_options(
        [
            Msf::OptString.new(
                'WORKSPACE',
                [
                    false,
                    "Specify the workspace for this module"
                ]
            )
        ],
        Msf::Module
    )
  end

  # @deprecated Use {#workspace_name}.
  #
  # Returns the current `Mdm::Workspace#name`
  #
  # @return [String] `Mdm::Workspace#name`
  def workspace
    ActiveSupport::Deprecation.warn(
        "#{self.class}##{__method__} is deprecated.  Use #{self.class}#workspace_name instead"
    )
    workspace_name
  end

  # Returns the current `Mdm::Workspace#name`
  #
  # @return [String] `Mdm::Workspace#name`
  def workspace_name
    data_store['WORKSPACE'] || framework.db.workspace_name
  end

  # The workspace with `Mdm::Workspace#name` equal to {#workspace_name}
  #
  # @return [Mdm::Workspace]
  def workspace_record
    framework.db.workspace(name: workspace_name)
  end
end