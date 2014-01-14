# Base class for classes that sync the cache to metadata in metasploit.
class Metasploit::Framework::Synchronization::Base < Metasploit::Model::Base
  include Metasploit::Framework::Transactional

  #
  # Attributes
  #

  # @!attribute [rw] source
  #   The source of information to synchronize to {#destination}.
  #
  #   @return [Object]
  attr_accessor :source

  #
  # Transactionals
  #

  # @!method synchronize
  #   Synchronizes {#source} to database.
  #
  #   @return [void]
  transactional :synchronize

  #
  # Validations
  #

  validates :source,
            presence: true
end