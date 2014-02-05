# Payload types
module Msf::Payload::Type
  #
  # Single payload type.  These types of payloads are self contained and
  # do not go through any staging.
  #
  Single = (1 << 0)

  #
  # The stager half of a staged payload.  Its responsibility in life is to
  # read in the stage and execute it.
  #
  Stager = (1 << 1)

  #
  # The stage half of a staged payload.  This payload performs whatever
  # arbitrary task it's designed to do, possibly making use of the same
  # connection that the stager used to read the stage in on, if
  # applicable.
  #
  Stage  = (1 << 2)
end