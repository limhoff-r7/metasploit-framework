require 'msf/base/sessions/command_shell'

class Msf::Sessions::CommandShellWindows < Msf::Sessions::CommandShell
  def initialize(*args)
    self.platform_fully_qualified_name = 'Windows'
    super
  end

  def shell_command_token(cmd,timeout = 10)
    shell_command_token_win32(cmd,timeout)
  end
end
