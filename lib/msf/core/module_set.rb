# -*- coding: binary -*-
require 'msf/core'

###
#
# A module set contains zero or more named module classes of an arbitrary
# type.
#
###
class Msf::ModuleSet < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] module_manager
  #   Collection of {Msf::ModuleSet module set}, one for each module type.
  #
  #   @return [Msf::ModuleManager]
  attr_accessor :module_manager

  # @!attribute [rw] module_type
  #   The `Metasploit::Model::Module::Class#module_type` for the metasploit Classes in this set.
  #
  #   @return [String] An element of `Metasploit::Model::Module::Type::ALL`.
  attr_accessor :module_type

  #
  # Validations
  #

  validates :module_manager,
            presence: true
  validates :module_type,
            inclusion: {
                in: Metasploit::Model::Module::Type::ALL
            }

  #
  # Methods
  #

  # Creates a metasploit instanc using the supplied `Mdm::Module::Class#reference_name`.
  # `Mdm::Module::Class#module_type` is assumed to be equal to {#module_type}.
  #
  # @param reference_name [String] An `Mdm::Module::Class#reference_name`.
  # @return (see Msf::ModuleManager#create)
  def create(reference_name)
    module_manager.create("#{module_type}/#{reference_name}")
  end
end
