# -*- coding: binary -*-

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/base/sessions'
require 'msf/core/option_container'

module Msf::Sessions::CommandShellOptions

  def before_register_session(session)
    if architecture_abbreviations.length == 1
      session.architecture_abbreviation = architecture_abbreviations.first
    end

    platforms = platform_list.platforms

    if platforms.length == 1
      platform = platforms.first
      session.platform_fully_qualified_name = platform.fully_qualified_name
    end
  end

  def initialize(info = {})
    super(info)

    register_advanced_options(
      [
        Msf::OptString.new('InitialAutoRunScript', [false, "An initial script to run on session creation (before AutoRunScript)", '']),
        Msf::OptString.new('AutoRunScript', [false, "A script to run automatically on session creation.", ''])
      ], self.class)
  end

  def on_session(session)
    super

    affixes = [
        :in,
        :out
    ]

    affixes.each do |affix|
      attribute = "user_#{affix}put"

      value = send(attribute)

      if value
        session.send("#{attribute}=", value)
      end
    end
  end

end
