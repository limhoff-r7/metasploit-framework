module Msf::Module::Target::SaveRegisters
  # The save registers declared for this target in the info Hash.  For the actual save registers for this target (i.e.
  # when it has no declared save registers and defers to the module's save registers), use {#save_registers}.
  #
  # @return [nil] if there are no save registers
  # @return [Array<String>] Array of save register names
  def declared_save_registers
    unless instance_variable_defined? :@declared_save_registers
      declared_save_registers = opts['SaveRegisters']

      unless declared_save_registers.nil?
        if declared_save_registers.empty?
          wlog(
              "'SaveRegisters' on target (#{name}) on exploit (#{metasploit_instance.reference_name}) is " \
            "#{declared_save_registers.inspect}, but the proper value when there are no save registers is `nil`, " \
            "so remove the 'SaveRegisters' entry from the target options."
          )
          declared_save_registers = nil
        else
          # ensure single Strings as treated as Arrays.
          declared_save_registers = Array.wrap(declared_save_registers)
        end
      end

      @declared_save_registers = declared_save_registers
    end

    @declared_save_registers
  end

  # Registers to be saved when generating nops.
  #
  # @return [Array<String>]
  def save_registers
    declared_save_registers || metasploit_instance.save_registers
  end
end