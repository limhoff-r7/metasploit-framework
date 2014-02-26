  # Empty template base class for command dispatchers.
  module Metasploit::Framework::UI::Text::DispatcherShell::CommandDispatcher

    #
    # Initializes the command dispatcher mixin.
    #
    def initialize(shell)
      self.shell = shell
      self.tab_complete_items = []
    end

    #
    # Returns {} for an empty set of commands.
    #
    # This method should be overridden to return a Hash with command
    # names for keys and brief help text for values.
    #
    def commands
      {}
    end

    #
    # Returns an empty set of commands.
    #
    # This method should be overridden if the dispatcher has commands that
    # should be treated as deprecated. Deprecated commands will not show up in
    # help and will not tab-complete, but will still be callable.
    #
    def deprecated_commands
      []
    end

    # @!method flush
    #   Flush the output `IO` attached to {#shell}.
    #
    #   @return [void]
    #
    # @!method print
    #   Prints message to {#shell}.
    #
    #   @return [void]
    #
    # @!method print_error
    #   Prints error to {#shell}.
    #
    #   @return [void]
    #
    # @!method print_good
    #   Prints a good message to {#shell}.
    #
    #   @return [void]
    #
    # @!method print_line
    #   Prints message followed by a newline to {#shell}.
    #
    #   @return [void]
    #
    # @!method print_status
    #   Prints a status message to {#shell}.
    #
    #   @return [void]
    #
    # @!method print_warning
    #   Prints a warning message to {#shell}.
    #
    #   @return [void]
    #
    # @!method tty?
    #   Whether the {#shell} is attached to a TTY.
    #
    #   @return [true] if {#shell} is attached to a TTY.
    #   @return [false] if {#shell} is not attached to a TTY or a mix of a TTY and something other non-TTY `IO`.
    #
    # @!method update_prompt
    #   Updates the shell prompt
    #
    #   @param prompt [String] text of prompt.
    #   @param prompt_char [String] character that signals the end of the `prompt` and the start of user input.
    #   @param module [Boolean] false for append.  true for replace.
    #   @return [void]
    #
    # @!method width
    #   The terminal width.
    #
    #   @return [80] if {#shell} is not connected to a TTY.
    #   @return [Integer] if {#shell} is connected to a TTY.
    delegate :flush,
             :print,
             :print_error,
             :print_good,
             :print_line,
             :print_status,
             :print_warning,
             :tty?,
             :update_prompt,
             :width,
             to: :shell

    #
    # Print a warning that the called command is deprecated and optionally
    # forward to the replacement +method+ (useful for when commands are
    # renamed).
    #
    def deprecated_cmd(method=nil, *args)
      cmd = caller[0].match(/`cmd_(.*)'/)[1]
      print_error "The #{cmd} command is DEPRECATED"
      if cmd == "db_autopwn"
        print_error "See http://r-7.co/xY65Zr instead"
      elsif method and self.respond_to?("cmd_#{method}")
        print_error "Use #{method} instead"
        self.send("cmd_#{method}", *args)
      end
    end

    def deprecated_help(method=nil)
      cmd = caller[0].match(/`cmd_(.*)_help'/)[1]
      print_error "The #{cmd} command is DEPRECATED"
      if cmd == "db_autopwn"
        print_error "See http://r-7.co/xY65Zr instead"
      elsif method and self.respond_to?("cmd_#{method}_help")
        print_error "Use 'help #{method}' instead"
        self.send("cmd_#{method}_help")
      end
    end

    def cmd_help_help
      print_line "There's only so much I can do"
    end

    #
    # Displays the help banner.  With no arguments, this is just a list of
    # all commands grouped by dispatcher.  Otherwise, tries to use a method
    # named cmd_<cmd>_help for the first dispatcher that has a command
    # named `cmd`.  If no such method exists, uses `cmd` as a regex to
    # compare against each enstacked dispatcher's name and dumps commands
    # of any that match.
    #
    def cmd_help(cmd=nil, *ignored)
      if cmd
        help_found = false
        cmd_found = false
        shell.dispatcher_stack.each do |dispatcher|
          next unless dispatcher.respond_to?(:commands)
          next if (dispatcher.commands.nil?)
          next if (dispatcher.commands.length == 0)

          if dispatcher.respond_to?("cmd_#{cmd}")
            cmd_found = true
            break unless dispatcher.respond_to? "cmd_#{cmd}_help"
            dispatcher.send("cmd_#{cmd}_help")
            help_found = true
            break
          end
        end

        unless cmd_found
          # We didn't find a cmd, try it as a dispatcher name
          shell.dispatcher_stack.each do |dispatcher|
            if dispatcher.name =~ /#{cmd}/i
              print_line(dispatcher.help_to_s)
              cmd_found = help_found = true
            end
          end
        end
        print_error("No help for #{cmd}, try -h") if cmd_found and not help_found
        print_error("No such command") if not cmd_found
      else
        print(shell.help_to_s)
      end
    end

    #
    # Tab completion for the help command
    #
    # By default just returns a list of all commands in all dispatchers.
    #
    def cmd_help_tabs(str, words)
      return [] if words.length > 1

      tabs = []
      shell.dispatcher_stack.each { |dispatcher|
        tabs += dispatcher.commands.keys
      }
      return tabs
    end

    alias cmd_? cmd_help

    #
    # Return a pretty, user-readable table of commands provided by this
    # dispatcher.
    #
    def help_to_s(opts={})
      # If this dispatcher has no commands, we can't do anything useful.
      return "" if commands.nil? or commands.length == 0

      # Display the commands
      tbl = Table.new(
        'Header'  => "#{self.name} Commands",
        'Indent'  => opts['Indent'] || 4,
        'Columns' =>
          [
            'Command',
            'Description'
          ],
        'ColProps' =>
          {
            'Command' =>
              {
                'MaxWidth' => 12
              }
          })

      commands.sort.each { |c|
        tbl << c
      }

      return "\n" + tbl.to_s + "\n"
    end

    #
    # No tab completion items by default
    #
    attr_accessor :shell, :tab_complete_items

    #
    # Provide a generic tab completion for file names.
    #
    # If the only completion is a directory, this descends into that directory
    # and continues completions with filenames contained within.
    #
    def tab_complete_filenames(str, words)
      matches = ::Readline::FILENAME_COMPLETION_PROC.call(str)
      if matches and matches.length == 1 and File.directory?(matches[0])
        dir = matches[0]
        dir += File::SEPARATOR if dir[-1,1] != File::SEPARATOR
        matches = ::Readline::FILENAME_COMPLETION_PROC.call(dir)
      end
      matches
    end

  end
