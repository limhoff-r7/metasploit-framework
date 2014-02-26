# -*- coding: binary -*-

#
# Standard library
#

require 'pp'
require 'shellwords'

#
# Gems
#

require 'active_support/concern'
require 'active_support/core_ext/module/delegation'

#
# Project
#

require 'rex/ui'

# The dispatcher shell module is designed to provide a generic means
# of processing various shell commands that may be located in
# different modules or chunks of codes.  These chunks are referred
# to as command dispatchers.  The only requirement for command dispatchers is
# that they prefix every method that they wish to be mirrored as a command
# with the cmd_ prefix.
module Metasploit::Framework::UI::Text::DispatcherShell
  extend ActiveSupport::Concern

  #
  # CONSTANT
  #

  # Captures trailing spaces at the end of a line.
  TRAILING_SPACE_REGEXP = /\s+$/

  module ClassMethods
    # Breaks up the line into words and attempts to repair unclosed double quotes so that {#tab_complete} will work when
    # only an opening double quote is present.
    #
    # @param line [String] line being tab completed.
    # @return [Array<String>]
    # @raise [ArgumentError] if `line` cannot be broken up into words (because unclosed double quotes cannot be
    #   repaired)
    def shell_words(line)
      retrying = false

      # Split the line up using Shellwords to support quoting and escapes
      begin
        Shellwords.split(line)
      rescue ::ArgumentError => error
        unless retrying
          # append a double quote to see if the line can be made parseable
          line += '"'
          retrying = true
          retry
        else
          # couldn't fix the unclosed double quotes, so no shell words were parseable
          raise error
        end
      end
    end
  end

  #
  # DispatcherShell derives from shell.
  #
  include Metasploit::Framework::UI::Text::Shell

  #
  # Initialize the dispatcher shell.
  #
  def initialize(prompt, prompt_char = '>', histfile = nil, framework = nil)
    super

    # Initialze the dispatcher array
    self.dispatcher_stack = []

    # Initialize the tab completion array
    self.tab_words = []
    self.on_command_proc = nil
  end

  #
  # This method accepts the entire line of text from the Readline
  # routine, stores all completed words, and passes the partial
  # word to the real tab completion function. This works around
  # a design problem in the Readline module and depends on the
  # Readline.basic_word_break_characters variable being set to \x00
  #
  def tab_complete(line)
    begin
      shell_words = self.class.shell_words(line)
    rescue ::ArgumentError => error
      print_error("#{error.class}: #{error}")

      []
    else
      # `Shellwords.split` will not return an empty word after the space so, need to determine if the trailing spaces
      # were captured by escapes ("one two\\ " -> ["one", "two"]) or if its a separator space
      # ("one two " -> ["one", "two"], but should be ["one", "two", ""]) and an empty word should be appended to
      # shell_words.
      line_trailing_spaces = line[TRAILING_SPACE_REGEXP]

      # if the string as a whole has no trailing spaces, then there's no need to check for trailing spaces on the last
      # shell word because the shell splitting will match the desired words for tab completion
      if line_trailing_spaces
        last_shell_word = shell_words.last
        last_shell_word_trailing_spaces = last_shell_word[TRAILING_SPACE_REGEXP]

        if last_shell_word_trailing_spaces.nil? || last_shell_word_trailing_spaces.length < line_trailing_spaces.length
          shell_words << ''
        end
      end

      # re-escape the shell words or after tab completing an escaped string, then the next tab completion will strip
      # the escaping
      escaped_shell_words = shell_words.collect { |shell_word|
        # don't escape the empty word added for tab completion as the tab completers are written to check for an empty
        # partial word to indicate this situation.  If '' is shell escaped it would become "''".
        if shell_word.empty?
          ''
        else
          Shellwords.escape(shell_word)
        end
      }

      # Place the word list into an instance variable
      self.tab_words = escaped_shell_words

      # Pop the last word and pass it to the real method
      tab_complete_stub(tab_words.pop)
    end
  end

  # Performs tab completion of a command, if supported
  # Current words can be found in self.tab_words
  #
  def tab_complete_stub(partial_word)
    if partial_word
      items = []

      dispatcher_stack.each { |dispatcher|
        # command completion
        if tab_words.empty? && dispatcher.respond_to?(:commands)
          items.concat(dispatcher.commands.keys)
        end

        # If the dispatcher exports a tab completion function, use it
        if dispatcher.respond_to? :tab_complete_helper
          dispatcher_items = dispatcher.tab_complete_helper(partial_word, tab_words)
        # otherwise use the default implementation of tab completion for dispatchers
        else
          dispatcher_items = tab_complete_helper(dispatcher, partial_word, tab_words)
        end

        # A nil response indicates no optional arguments
        if dispatcher_items.nil?
          if items.empty?
            items << ''
          end
        else
          # Otherwise we add the completion items to the list
          items.concat(dispatcher_items)
        end
      }

      matching_items = items.select { |item|
        item.start_with? partial_word
      }

      matching_items.collect { |matching_item|
        # Prepend the rest of the command as the underlying code allows for line replacement
        completed_words = [*tab_words, matching_item]
        # caller expected completed lines and not completed word lists
        completed_words.join(' ')
      }
    else
      nil
    end
  end

  #
  # Provide command-specific tab completion
  #
  def tab_complete_helper(dispatcher, str, words)
    items = []

    tabs_meth = "cmd_#{words[0]}_tabs"
    # Is the user trying to tab complete one of our commands?
    if (dispatcher.commands.include?(words[0]) and dispatcher.respond_to?(tabs_meth))
      res = dispatcher.send(tabs_meth, str, words)
      return [] if res.nil?
      items.concat(res)
    else
      # Avoid the default completion list for known commands
      return []
    end

    return items
  end

  #
  # Run a single command line.
  #
  def run_single(line)
    arguments = parse_line(line)
    method    = arguments.shift
    found     = false
    error_raised = false

    # If output is disabled output will be nil
    output.reset_color if (output)

    if (method)
      entries = dispatcher_stack.length

      dispatcher_stack.each { |dispatcher|
        next if not dispatcher.respond_to?('commands')

        begin
          if (dispatcher.commands.has_key?(method) or dispatcher.deprecated_commands.include?(method))
            self.on_command_proc.call(line.strip) if self.on_command_proc
            run_command(dispatcher, method, arguments)
          end
        rescue => error
          error_raised = true

          print_error(
            "Error while running command #{method}: #{error}" +
            "\n\nCall stack:\n#{error.backtrace.join("\n")}")
        rescue ::Exception => exception
          error_raised = true

          print_error(
            "Error while running command #{method}: #{exception}")
        else
          found = true
        end

        # If the dispatcher stack changed as a result of this command,
        # break out
        break if (dispatcher_stack.length != entries)
      }

      unless found || error_raised
        unknown_command(method, line)
      end
    end

    return found
  end

  #
  # Runs the supplied command on the given dispatcher.
  #
  def run_command(dispatcher, method, arguments)
    self.busy = true

    if(blocked_command?(method))
      print_error("The #{method} command has been disabled.")
    else
      dispatcher.send('cmd_' + method, *arguments)
    end
    self.busy = false
  end

  #
  # If the command is unknown...
  #
  def unknown_command(method, line)
    print_error("Unknown command: #{method}.")
  end

  #
  # Push a dispatcher to the front of the stack.
  #
  def enstack_dispatcher(dispatcher)
    self.dispatcher_stack.unshift(inst = dispatcher.new(self))

    inst
  end

  #
  # Pop a dispatcher from the front of the stacker.
  #
  def destack_dispatcher
    self.dispatcher_stack.shift
  end

  #
  # Adds the supplied dispatcher to the end of the dispatcher stack so that
  # it doesn't affect any enstack'd dispatchers.
  #
  def append_dispatcher(dispatcher)
    inst = dispatcher.new(self)
    self.dispatcher_stack.each { |disp|
      if (disp.name == inst.name)
        raise RuntimeError.new("Attempting to load already loaded dispatcher #{disp.name}")
      end
    }
    self.dispatcher_stack.push(inst)

    inst
  end

  #
  # Removes the supplied dispatcher instance.
  #
  def remove_dispatcher(name)
    self.dispatcher_stack.delete_if { |inst|
      (inst.name == name)
    }
  end

  #
  # Returns the current active dispatcher
  #
  def current_dispatcher
    self.dispatcher_stack[0]
  end

  #
  # Return a readable version of a help banner for all of the enstacked
  # dispatchers.
  #
  # See +CommandDispatcher#help_to_s+
  #
  def help_to_s(opts = {})
    str = ''

    dispatcher_stack.reverse.each { |dispatcher|
      str << dispatcher.help_to_s
    }

    return str
  end


  #
  # Returns nil for an empty set of blocked commands.
  #
  def blocked_command?(cmd)
    return false if not self.blocked
    self.blocked.has_key?(cmd)
  end

  #
  # Block a specific command
  #
  def block_command(cmd)
    self.blocked ||= {}
    self.blocked[cmd] = true
  end

  #
  # Unblock a specific command
  #
  def unblock_command(cmd)
    self.blocked || return
    self.blocked.delete(cmd)
  end


  attr_accessor :dispatcher_stack # :nodoc:
  attr_accessor :tab_words # :nodoc:
  attr_accessor :busy # :nodoc:
  attr_accessor :blocked # :nodoc:

end

require 'metasploit/framework/ui/text/dispatcher_shell/command_dispatcher'
