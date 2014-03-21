require 'active_support/core_ext/numeric/bytes'
module Msf

  class PayloadGeneratorError < StandardError
  end

  class EncoderSpaceViolation < PayloadGeneratorError
  end

  class IncompatibleArch < PayloadGeneratorError
  end

  class IncompatibleEndianess < PayloadGeneratorError
  end

  class IncompatiblePlatform < PayloadGeneratorError
  end

  class InvalidFormat < PayloadGeneratorError
  end

  class PayloadGenerator

    # @!attribute  add_code
    #   @return [String] The path to a shellcode file to execute in a seperate thread
    attr_accessor :add_code
    # @!attribute  arch
    #   @return [String] The CPU architecture to build the payload for
    attr_accessor :arch
    # @!attribute  badchars
    #   @return [String] The bad characters that can't be in the payload
    attr_accessor :badchars
    # @!attribute  cli
    #   @return [Boolean] Whether this is being run by a CLI script
    attr_accessor :cli
    # @!attribute  datastore
    #   @return [Hash] The datastore to apply to the payload module
    attr_accessor :datastore
    # @!attribute  encoder
    #   @return [String] The encoder(s) you want applied to the payload
    attr_accessor :encoder
    # @!attribute  format
    #   @return [String] The format you want the payload returned in
    attr_accessor :format
    # @!attribute  framework
    #   @return [Msf::Framework] The framework instance to use for generation
    attr_accessor :framework
    # @!attribute  iterations
    #   @return [Fixnum] The number of iterations to run the encoder
    attr_accessor :iterations
    # @!attribute  keep
    #   @return [Boolean] Whether or not to preserve the original functionality of the template
    attr_accessor :keep
    # @!attribute  nops
    #   @return [Fixnum] The size in bytes of NOP sled to prepend the payload with
    attr_accessor :nops
    # @!attribute  payload
    #   @return [String] The refname of the payload to generate
    attr_accessor :payload
    # @!attribute  platform
    #   @return [String] The platform to build the payload for
    attr_accessor :platform
    # @!attribute  space
    #   @return [Fixnum] The maximum size in bytes of the payload
    attr_accessor :space
    # @!attribute  stdin
    #   @return [String] The raw bytes of a payload taken from STDIN
    attr_accessor :stdin
    # @!attribute  template
    #   @return [String] The path to an executable template to use
    attr_accessor :template


    # @param opts [Hash] The options hash
    # @option opts [String] :payload (see #payload)
    # @option opts [String] :format (see #format)
    # @option opts [String] :encoder (see #encoder)
    # @option opts [Fixnum] :iterations (see #iterations)
    # @option opts [String] :arch (see #arch)
    # @option opts [String] :platform (see #platform)
    # @option opts [String] :badchars (see #badchars)
    # @option opts [String] :template (see #template)
    # @option opts [Fixnum] :space (see #space)
    # @option opts [Fixnum] :nops (see #nops)
    # @option opts [String] :add_code (see #add_code)
    # @option opts [Boolean] :keep (see #keep)
    # @option opts [Hash] :datastore (see #datastore)
    # @option opts [Msf::Framework] :framework (see #framework)
    # @option opts [Boolean] :cli (see #cli)
    # @raise [KeyError] if framework is not provided in the options hash
    def initialize(opts={})
      @add_code   = opts.fetch(:add_code, '')
      @arch       = opts.fetch(:arch, '')
      @badchars   = opts.fetch(:badchars, '')
      @cli        = opts.fetch(:cli, false)
      @datastore  = opts.fetch(:datastore, {})
      @encoder    = opts.fetch(:encoder, '')
      @format     = opts.fetch(:format, 'raw')
      @iterations = opts.fetch(:iterations, 1)
      @keep       = opts.fetch(:keep, false)
      @nops       = opts.fetch(:nops, 0)
      @payload    = opts.fetch(:payload, '')
      @platform   = opts.fetch(:platform, '')
      @space      = opts.fetch(:space, 1.gigabyte)
      @stdin      = opts.fetch(:stdin, nil)
      @template   = opts.fetch(:template, '')

      @framework  = opts.fetch(:framework)

      raise ArgumentError, "Invalid Payload Selected" unless payload_is_valid?
      raise ArgumentError, "Invalid Format Selected" unless format_is_valid?
    end

    # This method takes the shellcode generated so far and adds shellcode from
    # a supplied file. The added shellcode is executed in a seperate thread
    # from the main payload.
    # @param shellcode [String] The shellcode to add to
    # @return [String] the combined shellcode which executes the added code in a seperate thread
    def add_shellcode(shellcode)
      if add_code.present? and platform_list.platforms.map(&:fully_qualified_name).include? 'Windows' and arch == "x86"
        cli_print "Adding shellcode from #{add_code} to the payload"
        shellcode_file = File.open(add_code)
        shellcode_file.binmode
        added_code = shellcode_file.read
        shellcode_file.close
        shellcode = ::Msf::Util::EXE.win32_rwx_exec_thread(shellcode,0,'end')
        shellcode << added_code
      else
        shellcode.dup
      end
    end

    # This method takes a payload module and tries to reconcile a chosen
    # arch with the arches supported by the module.
    # @param mod [Msf::Payload] The module class to choose an arch for
    # @return [String] String form of the Arch if a valid arch found
    # @return [Nil] if no valid arch found
    def choose_arch(mod)
      if arch.blank?
        @arch = mod.arch.first
        cli_print "No Arch selected, selecting Arch: #{arch} from the payload"
        return mod.arch.first
      elsif mod.arch.include? arch
        return arch
      else
        return nil
      end
    end

    # This method takes a payload module and tries to reconcile a chosen
    # platform with the platforms supported by the module.
    # @param mod [Msf::Payload] The module class to choose a platform for
    # @return [Msf::Module::PlatformList] The selected platform list
    def choose_platform(mod)
      chosen_platform = platform_list
      if chosen_platform.platforms.empty?
        chosen_platform = mod.platform
        cli_print "No platform was selected, choosing #{chosen_platform.platforms.first} from the payload"
        @platform = mod.platform_list.platforms.first.fully_qualified_name
      elsif (chosen_platform & mod.platform).empty?
        chosen_platform = Msf::Module::PlatformList.new
      end
      chosen_platform
    end

    # This method takes the shellcode generated so far and iterates through
    # the chosen or compatible encoders. It attempts to encode the payload
    # with each encoder until it finds one that works.
    # @param shellcode [String] The shellcode to encode
    # @return [String] The encoded shellcode
    def encode_payload(shellcode)
      shellcode = shellcode.dup
      encoder_list = get_encoders
      cli_print "Found #{encoder_list.count} compatible encoders"
      if encoder_list.empty?
        shellcode
      else
        encoder_list.each do |encoder_mod|
          cli_print "Attempting to encode payload with #{iterations} iterations of #{encoder_mod.refname}"
          begin
            return run_encoder(encoder_mod, shellcode.dup)
          rescue ::Msf::EncoderSpaceViolation => e
            cli_print "#{encoder_mod.refname} failed with #{e.message}"
            next
          rescue ::Msf::EncodingError => e
            cli_print "#{encoder_mod.refname} failed with #{e.message}"
            next
          end
        end
        raise ::Msf::EncodingError, "No Encoder Succeeded"
      end
    end

    # This returns a hash for the exe format generation of payloads
    # @return [Hash] The hash needed for generating an executable format
    def exe_options
      opts = { inject: keep }
      unless template.blank?
        opts[:template_path] = File.dirname(template)
        opts[:template]      = File.basename(template)
      end
      opts
    end

    # This method takes the payload shellcode and formats it appropriately based
    # on the selected output format.
    # @param shellcode [String] the processed shellcode to be formatted
    # @return [String] The final formatted form of the payload
    def format_payload(shellcode)
      case format.downcase
        when "js_be"
          if Rex::Arch.endian(arch) != ENDIAN_BIG
            raise IncompatibleEndianess, "Big endian format selected for a non big endian payload"
          else
            ::Msf::Simple::Buffer.transform(shellcode, format)
          end
        when *::Msf::Simple::Buffer.transform_formats
          ::Msf::Simple::Buffer.transform(shellcode, format)
        when *::Msf::Util::EXE.to_executable_fmt_formats
          ::Msf::Util::EXE.to_executable_fmt(framework, arch, platform_list, shellcode, format, exe_options)
        else
          raise InvalidFormat, "you have selected an invalid payload format"
      end
    end

    # This method generates Java payloads which are a special case.
    # They can be generated in raw or war formats, which respectively
    # produce a JAR or WAR file for the java payload.
    # @return [String] Java payload as a JAR or WAR file
    def generate_java_payload
      payload_module = framework.payloads.create(payload)
      case format
        when "raw"
          if payload_module.respond_to? :generate_jar
            payload_module.generate_jar.pack
          else
            raise InvalidFormat, "#{payload} is not a Java payload"
          end
        when "war"
          if payload_module.respond_to? :generate_war
            payload_module.generate_war.pack
          else
            raise InvalidFormat, "#{payload} is not a Java payload"
          end
        else
          raise InvalidFormat, "#{format} is not a valid format for Java payloads"
      end
    end

    # This method is a wrapper around all of the other methods. It calls the correct
    # methods in order based on the supplied options and returns the finished payload.
    # @return [String] A string containing the bytes of the payload in the format selected
    def generate_payload
      if platform == "java" or arch == "java" or payload.start_with? "java/"
        generate_java_payload
      else
        raw_payload = generate_raw_payload
        raw_payload = add_shellcode(raw_payload)
        encoded_payload = encode_payload(raw_payload)
        encoded_payload = prepend_nops(encoded_payload)
        format_payload(encoded_payload)
      end
    end


    # This method generates the raw form of the payload as generated by the payload module itself.
    # @raise [Msf::IncompatiblePlatform] if no platform was selected for a stdin payload
    # @raise [Msf::IncompatibleArch] if no arch was selected for a stdin payload
    # @raise [Msf::IncompatiblePlatform] if the platform is incompatible with the payload
    # @raise [Msf::IncompatibleArch] if the arch is incompatible with the payload
    # @return [String] the raw bytes of the payload to be generated
    def generate_raw_payload
      if payload == 'stdin'
        if arch.blank?
          raise IncompatibleArch, "You must select an arch for a custom payload"
        elsif platform.blank?
          raise IncompatiblePlatform, "You must select a platform for a custom payload"
        end
        stdin
      else
        payload_module = framework.payloads.create(payload)

        chosen_platform = choose_platform(payload_module)
        if chosen_platform.platforms.empty?
          raise IncompatiblePlatform, "The selected platform is incompatible with the payload"
        end

        chosen_arch = choose_arch(payload_module)
        unless chosen_arch
          raise IncompatibleArch, "The selected arch is incompatible with the payload"
        end

        payload_module.generate_simple(
            'Format'   => 'raw',
            'Options'  => datastore,
            'Encoder'  => nil
        )
      end
    end

    # This method returns an array of encoders that either match the
    # encoders selected by the user, or match the arch selected.
    # @return [Array<Msf::Encoder>] An array of potential encoders to use
    def get_encoders
      encoders = []

      if encoder.present?
        # Allow comma seperated list of encoders so users can choose several
        encoder.split(',').each do |chosen_encoder|
          encoder_instance  = framework.encoders.create(chosen_encoder)

          if encoder_instance
            encoders << encoder_instance
          end
        end
      elsif badchars.present?
        framework.encoders.each_module_ranked('Arch' => [arch]) do |name, mod|
          encoder_instance = framework.encoders.create(name)

          if encoder_instance
            encoders << encoder_instance
          end
        end
      end

      encoders.sort_by { |my_encoder| my_encoder.rank_number }.reverse
    end

    # Returns a PlatformList object based on the platform string given at creation.
    # @return [Msf::Module::PlatformList] It will be empty if no valid platforms found
    def platform_list
      if platform.blank?
        list = Msf::Module::PlatformList.new
      else
        begin
          list = ::Msf::Module::PlatformList.transform(platform)
        rescue
          list = Msf::Module::PlatformList.new
        end
      end
      list
    end

    # This method takes an encoded payload and prepends a NOP Sled to it
    # with a size based on the nops value given to the generator.
    # @param shellcode [String] The shellcode to prepend the NOPs to
    # @return [String] the shellcode with the appropriate nopsled affixed
    def prepend_nops(shellcode)
      shellcode_with_nops = shellcode

      if nops > 0
        cache_nop_instances = Mdm::Module::Instance.with_module_type(
            'nop'
        ).intersecting_architecture_abbreviations(
            [arch]
        )
        cache_nop_classes = Mdm::Module::Class.with_module_instances(cache_nop_instances).ranked
        nop_instances = Metasploit::Framework::Module::Instance::Enumerator.new(
            cache_module_classes: cache_nop_classes,
            universal_module_instance_creator: framework.modules
        )
        nop_instances.valid!

        nop_instances.each do |nop_instance|
          nop_sled = nop_instance.generate_sled(
              nops,
              {
                  'BadChars' => badchars,
                  'SaveRegisters' => %w{ebp edi esi esp}
              }
          )

          if nop_sled
            cli_print "Successfully added NOP sled from #{nop_instance.reference_name}"
            shellcode_with_nops = nop_sled + shellcode

            break
          end
        end
      end

      shellcode_with_nops
    end

    # This method runs a specified encoder, for a number of defined iterations against the shellcode.
    # @param encoder_module [Msf::Encoder] The Encoder to run against the shellcode
    # @param shellcode [String] The shellcode to be encoded
    # @return [String] The encoded shellcode
    # @raise [Msf::EncoderSpaceViolation] If the Encoder makes the shellcode larger than the supplied space limit
    def run_encoder(encoder_module, shellcode)
      iterations.times do |x|
        shellcode = encoder_module.encode(shellcode.dup, badchars, nil, platform_list)
        cli_print "#{encoder_module.refname} succeeded with size #{shellcode.length} (iteration=#{x})"
        raise EncoderSpaceViolation, "encoder has made a buffer that is too big" if shellcode.length > space
      end
      shellcode
    end

    private

    # This method prints output to the console if running in CLI mode
    # @param [String] message The message to print to the console.
    def cli_print(message= '')
      $stderr.puts message if cli
    end

    # This method checks if the Generator's selected format is valid
    # @return [True] if the format is valid
    # @return [False] if the format is not valid
    def format_is_valid?
      formats = (::Msf::Util::EXE.to_executable_fmt_formats + ::Msf::Simple::Buffer.transform_formats).uniq
      formats.include? format.downcase
    end

    # This method checks if the Generator's selected payload is valid
    # @return [True] if the payload is a valid Metasploit Payload
    # @return [False] if the payload is not a valid Metasploit Payload
    def payload_is_valid?
      payload == 'stdin' || Mdm::Module::Class.where(module_type: 'payload', reference_name: payload).exists?
    end

  end
end
