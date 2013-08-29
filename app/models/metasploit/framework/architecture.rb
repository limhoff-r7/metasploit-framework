class Metasploit::Framework::Architecture < Metasploit::Model::Base
	include Metasploit::Model::Architecture

  #
  # Attributes
  #

  # @!attribute [rw] abbreviation
  #   Abbreviation used for the architecture.  Will match ARCH constants in metasploit-framework.
  #
  #   @return [String]
  attr_accessor :abbreviation

  # @!attribute [rw] bits
  #   Number of bits supported by this architecture.
  #
  #   @return [32] if 32-bit
  #   @return [64] if 64-bit
  #   @return [nil] if bits aren't applicable, such as for non-CPU architectures like ruby, etc.
  attr_accessor :bits

  # @!attribute [rw] endianness
  #   The endianness of the architecture.
  #
  #   @return ['big'] if big endian
  #   @return ['little'] if little endian
  #   @return [nil] if endianness is not applicable, such as for software architectures like tty.
  attr_accessor :endianness

  # @!attribute [rw] family
  #   The CPU architecture family.
  #
  #   @return [String] if a CPU architecture.
  #   @return [nil] if not a CPU architecture.
  attr_accessor :family

	# @!attribute [rw]
	#   ID for ROM
	#
	#   @return [Integer]
	attr_accessor :id

  # @!attribute [rw] summary
  #   Sentence length summary of architecture.  Usually an expansion of the abbreviation or initialism in the
  #   {#abbreviation} and the {#bits} and {#endianness} in prose.
  #
  #   @return [String]
  attr_accessor :summary
end