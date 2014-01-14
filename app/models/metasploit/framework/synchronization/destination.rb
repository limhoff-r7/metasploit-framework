# Synchronizes {#source} model to given {#destination} in database.
class Metasploit::Framework::Synchronization::Destination < Metasploit::Framework::Synchronization::Base
  #
  # Attributes
  #

  # @!attribute [rw] destination
  #   The destination to be synchronized with {#source}.
  #
  #   @return [ActiveRecord::Base]
  attr_accessor :destination

  #
  # Validations
  #

  validates :destination,
            presence: true

  private

  def added_attributes_set
    @added_attributes_set ||= source_attributes_set - destination_attributes_set
  end

  def removed_attributes_set
    @removed_attributes_set ||= destination_attributes_set - source_attributes_set
  end
end