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

  # @!attribute [rw] module_type
  #   The `Metasploit::Model::Module::Class#module_type` for the metasploit Classes in this set.
  #
  #   @return [String] An element of `Metasploit::Model::Module::Type::ALL`.
  attr_accessor :module_type

  # @!attribute [rw] universal_module_instance_creator
  #   Creator that can create modules of any module type.
  #
  #   @return [Metasploit::Framework::Module::Instance::Creator::Universal]
  attr_accessor :universal_module_instance_creator

  #
  # Validations
  #

  validates :module_type,
            inclusion: {
                in: Metasploit::Model::Module::Type::ALL
            }
  validates :universal_module_instance_creator,
            presence: true

  #
  # Methods
  #

  # Creates an {Msf::Module} instance using the supplied `Mdm::Module::Class#reference_name`.
  # `Mdm::Module::Class#module_type` is assumed to be equal to {#module_type}.
  #
  # @param reference_name [String] An `Mdm::Module::Class#reference_name`.
  # @return (see Metasploit::Framework::Module::Instance::Creator::Universal#create)
  def create(reference_name)
    universal_module_instance_creator.create("#{module_type}/#{reference_name}")
  end
end
