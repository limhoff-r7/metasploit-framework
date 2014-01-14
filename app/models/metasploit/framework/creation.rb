class Metasploit::Framework::Creation < Metasploit::Model::Base
  include Metasploit::Framework::Transactional

  #
  # Transactionals
  #

  # @!method create
  #   Creates records in the database.
  #
  #   @return [void]
  transactional :create
end