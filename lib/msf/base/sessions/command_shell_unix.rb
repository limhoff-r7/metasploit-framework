require 'msf/base/sessions/command_shell'

class Msf::Sessions::CommandShellUnix < Msf::Sessions::CommandShell
  def initialize(*args)
    self.platform_fully_qualified_name = 'UNIX'

    super
  end

  def shell_command_token(cmd, timeout = 10)
    shell_command_token_unix(cmd, timeout)
  end
end