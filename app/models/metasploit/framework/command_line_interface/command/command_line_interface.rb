# This user interface allows users to interact with the framework through a
# command line interface (CLI) rather than having to use a prompting console
# or web-based interface.
class Metasploit::Framework::CommandLineInterface::Command::CommandLineInterface < Metasploit::Framework::CommandLineInterface::Command::Base
  include Metasploit::Framework::Command::Parent

  #
  # CONSTANTS
  #

  INDENT =  ' ' * 3
  SUBCOMMAND_NAME_BY_FLAG = {
      'a' => :advanced,
      'ac' => :actions,
      'c' => :check,
      'e' => :execute,
      'h' => :help,
      'i' => :ids_evasion,
      'o' => :options,
      'p' => :payloads,
      's' => :summary,
      't' => :targets
  }

  #
  # Attributes
  #

  # @!attribute [rw] framework
  #   The framework being accessed from the command-line
  #
  #   @return [Msf::Simple::Framework]
  attr_writer :framework

  # @!attribute [rw] auxiliary_instance
  #   The auxiliary instance specified as the first argument.
  #
  #   @return [Msf::Auxiliary]
  attr_accessor :auxiliary_instance

  # @!attribute [rw] encoder_instance
  #   The encoder instance specified with 'encoder=<reference name>'.
  #
  #   @return [Msf::Encoder]
  attr_accessor :encoder_instance

  # @!attribute [rw] exploit_instance
  #   The exploit instance specified as the first argument.
  #
  #   @return [Msf::Exploit]
  attr_accessor :exploit_instance

  # @!attribute [rw] nop_instance
  #   The nop instance specified with 'nop=<reference name>'.
  #
  #   @return [Msf::Nop]
  attr_accessor :nop_instance

  # @!attribute [rw] payload_instance
  #   The payload instance specified with 'payload=<reference name>'.
  #
  #   @return [Msf::Payload]
  attr_accessor :payload_instance

  # @!attribute [rw] post_instance
  #   The post instance specified with 'post=<reference name>'.
  #
  #   @return [Msf::Post]
  attr_accessor :post_instance

  #
  # Subcommands
  #

  subcommand :help,
             default: true

  #
  # Methods
  #

  #
  # Loads up everything in framework, and then returns the module list
  #
  def dump_module_list
    lines = []

    ['auxiliary', 'exploit'].each do |module_type|
      directory =  Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE[module_type]
      title = directory.titleize
      lines << title

      module_instances = Mdm::Module::Instance.joins(
          :module_class
      ).where(
          Mdm::Module::Class.arel_table[:module_type].eq(module_type)
      )

      printer = TablePrint::Printer.new(
          module_instances,
          [
              'module_class.full_name',
              'name'
          ]
      )

      max_width_before = TablePrint::Config.max_width
      TablePrint::Config.max_width = Float::INFINITY

      begin
        lines << printer.table_print
      ensure
        TablePrint::Config.max_width = max_width_before
      end
    end

    lines.join("\n")
  end

  def framework
    @framework ||= Msf::Simple::Framework.create
  end

  #
  # Initializes exploit/payload/encoder/nop modules.
  #
  def init_modules
    $stdout.puts "[*] Initializing modules..."

    module_name = @args[:module_name]
    modules = {
        :module  => nil,  # aux or exploit instance
        :payload => nil,  # payload instance
        :encoder => nil,  # encoder instance
        :nop     => nil   # nop instance
    }

    # Load up all the possible modules, this is where things get slow again
    framework.add_module_paths
    if (@framework.modules.module_load_error_by_path.length > 0)
      print("Warning: The following modules could not be loaded!\n\n")

      @framework.modules.module_load_error_by_path.each do |path, error|
        print("\t#{path}: #{error}\n\n")
      end

      return {}
    end

    # Determine what type of module it is
    if module_name =~ /exploit\/(.*)/
      modules[:module] = @framework.exploits.create($1)
    elsif module_name =~ /auxiliary\/(.*)/
      modules[:module] = @framework.auxiliary.create($1)
    else
      modules[:module] = @framework.exploits.create(module_name)
      if modules[:module].nil?
        # Try falling back on aux modules
        modules[:module] = @framework.auxiliary.create(module_name)
      end
    end

    if modules[:module].nil?
      # Still nil? Ok then, probably invalid
      return {}
    end

    modules[:module].init_ui(
        Rex::Ui::Text::Input::Stdio.new,
        Rex::Ui::Text::Output::Stdio.new
    )

    # Import options
    begin
      modules[:module].datastore.import_options_from_s(@args[:params].join('_|_'), '_|_')
    rescue Rex::ArgumentParseError => e
      raise e
    end

    # Create the payload to use
    if (modules[:module].datastore['PAYLOAD'])
      modules[:payload] = @framework.payloads.create(modules[:module].datastore['PAYLOAD'])
      if modules[:payload]
        modules[:payload].datastore.import_options_from_s(@args[:params].join('_|_'), '_|_')
      end
    end

    # Create the encoder to use
    if modules[:module].datastore['ENCODER']
      modules[:encoder] = @framework.encoders.create(modules[:module].datastore['ENCODER'])
      if modules[:encoder]
        modules[:encoder].datastore.import_options_from_s(@args[:params].join('_|_'), '_|_')
      end
    end

    # Create the NOP to use
    if modules[:module].datastore['NOP']
      modules[:nop] = @framework.nops.create(modules[:module].datastore['NOP'])
      if modules[:nop]
        modules[:nop].datastore.import_options_from_s(@args[:params].join('_|_'), '_|_')
      end
    end

    modules
  end

  def show_payloads(m)
    readable = Msf::Serializer::ReadableText
    txt      = "Compatible payloads"
    $stdout.puts("\n" + readable.dump_compatible_payloads(m[:module], INDENT, txt))
  end


  def show_targets(m)
    readable = Msf::Serializer::ReadableText
    $stdout.puts("\n" + readable.dump_exploit_targets(m[:module], INDENT))
  end


  def show_actions(m)
    readable = Msf::Serializer::ReadableText
    $stdout.puts("\n" + readable.dump_auxiliary_actions(m[:module], INDENT))
  end


  def show_check(m)
    begin
      if (code = m[:module].check_simple(
          'LocalInput'    => Rex::Ui::Text::Input::Stdio.new,
          'LocalOutput'   => Rex::Ui::Text::Output::Stdio.new))
        stat = (code == Msf::Exploit::CheckCode::Vulnerable) ? '[+]' : '[*]'

        $stdout.puts("#{stat} #{code[1]}")
      else
        $stdout.puts("Check failed: The state could not be determined.")
      end
    rescue
      $stdout.puts("Check failed: #{$!}")
    end
  end


  def execute_module(m)
    con = Msf::Ui::Console::Driver.new(
        Msf::Ui::Console::Driver::DEFAULT_PROMPT,
        Msf::Ui::Console::Driver::DEFAULT_PROMPT_CHAR,
        {
            'Framework' => @framework,
            # When I use msfcli, chances are I want speed, so ASCII art fanciness
            # probably isn't much of a big deal for me.
            'DisableBanner' => true
        })

    module_class = (m[:module].fullname =~ /^auxiliary/ ? 'auxiliary' : 'exploit')

    con.run_single("use #{module_class}/#{m[:module].refname}")

    # Assign console parameters
    @args[:params].each do |arg|
      k,v = arg.split("=", 2)
      con.run_single("set #{k} #{v}")
    end

    # Run the exploit
    con.run_single("exploit")

    # If we have sessions or jobs, keep running
    if @framework.sessions.length > 0 or @framework.jobs.length > 0
      con.run
    else
      con.run_single("quit")
    end
  end


  #
  # Selects a mode chosen by the user and run it
  #
  def engage_mode(modules)
    case @args[:mode].downcase
      when 'h'
        usage
      when "s"
        dump_instances(:module)
      when "o"
        dump_instances(:options)
      when "a"
        dump_instances(:advanced_options)
      when "i"
        dump_instances(:evasion_options)
      when "p"
        if modules[:module].file_path =~ /auxiliary\//i
          $stdout.puts("\nError: This type of module does not support payloads")
        else
          show_payloads(modules)
        end
      when "t"
        puts
        if modules[:module].file_path =~ /auxiliary\//i
          $stdout.puts("\nError: This type of module does not support targets")
        else
          show_targets(modules)
        end
      when "ac"
        if modules[:module].file_path =~ /auxiliary\//i
          show_actions(modules)
        else
          $stdout.puts("\nError: This type of module does not support actions")
        end
      when "c"
        show_check(modules)
      when "e"
        execute_module(modules)
      else
        usage("Invalid mode #{@args[:mode]}")
    end
  end


  def run!
    if @args[:module_name] == "-h"
      usage()
      exit
    end

    $:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']
    require 'msfenv'
    require 'msf/ui'
    require 'msf/base'

    if @args[:module_name].nil?
      ext = dump_module_list
      usage(nil, ext)
      exit
    end

    begin
      modules = init_modules
    rescue Rex::ArgumentParseError => e
      puts "[!] Error: #{e.message}\n\n"
      exit
    end

    if modules[:module].nil?
      usage("Invalid module: #{@args[:module_name]}")
      exit
    end

    # Process special var/val pairs...
    Msf::Ui::Common.process_cli_arguments(@framework, @args[:params])

    engage_mode(modules)
    $stdout.puts
  end

  private

  def dump_instances(dump_type)
    dump_method = Msf::Serializer::ReadableText.method("dump_#{dump_type}")

    each_instance do |instance|
      puts "#{instance.module_type}:"
      puts dump_method.call(instance, INDENT)
    end
  end

  def each_instance
    Metasploit::Model::Module::Type::ALL.each do |module_type|
      instance = send("#{module_type}_instance")

      if instance
        yield instance
      end
    end
  end

  def parse_words
    unless @words_parsed
      if words.length > 0
        flag = words.last.downcase
        self.subcommand_name = SUBCOMMAND_NAME_BY_FLAG[flag]
      end

      @words_parsed = true
    end
  end
end
