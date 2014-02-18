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

  def self.module_names
    @module_names ||= MODULE_RELATIVE_NAMES.collect { |relative_name|
      "Msf::Handler::#{relative_name}"
    }
  end
end