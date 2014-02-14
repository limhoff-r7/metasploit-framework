module Msf::Module::SaveRegisters
  # The list of registers that should be saved by any NOP generators or encoders, if possible.
  #
  # @return [Array<String>] if any save registers are declared.
  # @return [nil] if no save registers are declared or the set of declared registers is empty.
  def save_registers
    unless instance_variable_defined? :@save_registers
      save_registers = module_info['SaveRegisters']

      unless save_registers.nil?
        if save_registers.empty?
          wlog("'SaveRegisters' on exploit (#{reference_name}) is #{save_registers.inspect}, but when the proper " \
          "value when there ae no save registers is `nil`, so remove the 'SaveRegisters' entry from the module info."
          )
          save_registers = nil
        else
          save_registers = Array.wrap(save_registers)
        end
      end

      @save_registers = save_registers
    end

    @save_registers
  end
end