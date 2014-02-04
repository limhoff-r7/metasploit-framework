module Metasploit::Framework::Deprecation
  def self.rename_methods(receiver, current_name_by_deprecated_name)
    current_name_by_deprecated_name.each do |deprecated_name, current_name|
      # Use string eval so that caller reports correct method name
      receiver.module_eval(<<-end_eval, __FILE__, __LINE__ + 1)
        def #{deprecated_name}(*args, &block)
          ::Metasploit::Framework::Deprecation.warn(self, :#{deprecated_name}, :#{current_name})
          send(:#{current_name}, *args, &block)
        end
      end_eval
    end
  end

  def self.warn(receiver, deprecated_name, current_name)
    method = receiver.method(deprecated_name)
    ActiveSupport::Deprecation.warn "#{method.owner}##{deprecated_name} is deprecated. Use #{method.owner}##{current_name} instead.",
                                    # have to pass caller so this method isn't included in callstack
                                    caller
  end
end