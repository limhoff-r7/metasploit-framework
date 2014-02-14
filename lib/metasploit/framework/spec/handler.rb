module Metasploit::Framework::Spec::Handler
  MODULE_RELATIVE_NAMES = %w{
    BindTcp
    FindPort
    FindShell
    FindTag
    FindTty
    None
    ReverseHttp
    ReverseHttps
    ReverseHttpsProxy
    ReverseIPv6Http
    ReverseIPv6Https
    ReverseTcp
    ReverseTcpAllPorts
    ReverseTcpDouble
    ReverseTcpDoubleSSL
    ReverseTcpSsl
  }

  def self.module_names_by_type
    @module_names_by_type ||= MODULE_RELATIVE_NAMES.each_with_object({})  { |module_relative_name, module_names_by_type|
      module_name = "Msf::Handler::#{module_relative_name}"
      handler_module = module_name.constantize
      type = handler_module.handler_type

      module_names_by_type[type] ||= []
      module_names_by_type[type] << module_name
    }
  end
end