class Metasploit::Framework::Payload::Assembled < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] data
  #   The assembled shellcoded data.
  #
  #   @return [String] {Metasm::EncodedData#data} or a plain `String` for pre-assembled payloads declared in the payload
  #     module.
  attr_writer :data

  # @!attribute [rw] offset_relative_address_and_type_by_name
  #   @note DO NOT include 'RAW' type offsets in this list as this list should be valid for usage
  #     with {Msf::Payload#substitute_vars}, which does not handle 'RAW'.
  #   The offset relative address and type by name
  #
  #   @return [Hash{String => Array<(Integer, String)>}]
  attr_writer :offset_relative_address_and_type_by_name

  #
  # Methods
  #

  # Data can be empty for shellcode-less payloads like 'cmd/unix/interact'.
  #
  # @return [String] ''
  def data
    @data ||= ''
  end

  def offset_relative_address_and_type_by_name
    @offset_relative_address_and_type_by_name ||= {}
  end
end