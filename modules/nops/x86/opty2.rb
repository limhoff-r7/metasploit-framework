##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex/nop/opty2'


###
#
# Opty2
# -----
#
# This class implements single-byte NOP generation for X86.  It takes from
# ADMmutate and from spoonfu.
#
###
class Metasploit3 < Msf::Nop

  # Must be better than rank for single_byte so opty2 is favored over single_byte
  Rank = ExcellentRanking

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Opty2',
            'Description' => 'Opty2 multi-byte NOP generator',
            'Author'      => [ 'spoonm', 'optyx' ],
            'License'     => MSF_LICENSE,
            'Arch'        => ARCH_X86
        )
    )
  end

  def generate_sled(length, opts = {})
    opty = Rex::Nop::Opty2.new(
      opts['BadChars'] || '',
      opts['SaveRegisters'])

    opty.generate_sled(length)
  end

end
