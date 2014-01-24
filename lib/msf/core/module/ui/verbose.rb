require 'msf/core/module/data_store'
require 'msf/core/module/options'
require 'msf/core/option_container'

module Msf::Module::UI::Verbose
  include Msf::Module::DataStore
  include Msf::Module::Options

  def initialize(info={})
    super

    register_advanced_options(
        [
            Msf::OptBool.new(
                'VERBOSE',
                [
                    false,
                    'Enable detailed status messages',
                    false
                ]
            )
        ],
        Msf::Module
    )
  end

  # Verbose version of #print_debug
  def vprint_debug(msg)
    print_debug(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end

  # Verbose version of #print_error
  def vprint_error(msg)
    print_error(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end

  # Verbose version of #print_good
  def vprint_good(msg)
    print_good(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end

  # Verbose version of #print_line
  def vprint_line(msg)
    print_line(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end

  # Verbose version of #print_status
  def vprint_status(msg)
    print_status(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end

  # Verbose version of #print_warning
  def vprint_warning(msg)
    print_warning(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end
end