# -*- coding: binary -*-

require 'msf/core/post/windows'

module Msf::Post::Windows::ExtAPI

  def load_extapi
    if session.extapi
      return true
    else
      begin
        return session.core.use("extapi")
      rescue Errno::ENOENT
        print_error("Unable to load Extended API.")
        return false
      end
    end
  end

end
