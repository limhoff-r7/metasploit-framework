# -*- coding: binary -*-
require 'msf/core'

# @note If you have a `Mdm::Module::Class`, use
#   {Metasploit::Framework::Module::Instance::Creator::Universal#create_from_module_class} as that will save looking up
#   the `Mdm::Module::Class` again.
#
# Creates {Msf::Module} instances of a specific {#module_type} using `Mdm::Module::Class#reference_name` for {#create}.
class Metasploit::Framework::Module::Instance::Creator::Type < Metasploit::Model::Base
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

  # @note If you have a full `Mdm::Module::Class`, use
  #   {Metasploit::Framework::Module::Instance::Creator::Universal#create_from_module_calss} as that will save looking
  #   up the `Mdm::Module::Class` again.
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
