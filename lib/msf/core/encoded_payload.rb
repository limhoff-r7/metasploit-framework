# -*- coding: binary -*-

require 'msf/core'

module Msf

###
#
# This class wrappers an encoded payload buffer and the means used to create
# one.
#
###
class EncodedPayload
  include Framework::Offspring

  #
  # Attributes
  #

  # @!attribute [rw] payload_instance
  #   Instance of payload class
  #
  #   @return [Msf::Payload]
  attr_accessor :payload_instance

  #
  # Methods
  #

  #
  # This method creates an encoded payload instance and returns it to the
  # caller.
  #
  def self.create(pinst, reqs = {})
    # Create the encoded payload instance
    p = EncodedPayload.new(pinst.framework, pinst, reqs)

    p.generate(reqs['Raw'])

    return p
  end

  # Creates an instance of an EncodedPayload.
  #
  # @param framework [Msf::Simple::Framework]
  # @param payload_instance [Msf::Payload] instance of payload class to be encoded.
  # @param reqs [Array<String>] requirements
  def initialize(framework, payload_instance, reqs)
    self.framework = framework
    self.payload_instance     = payload_instance
    self.reqs      = reqs
  end

  #
  # This method generates the full encoded payload and returns the encoded
  # payload buffer.
  #
  # @return [String] The encoded payload.
  def generate(raw = nil)
    self.raw           = raw
    self.encoded       = nil
    self.nop_sled_size = 0
    self.nop_sled      = nil
    self.encoder       = nil
    self.nop           = nil
    self.iterations    = reqs['Iterations'].to_i
    self.iterations    = 1 if self.iterations < 1

    # Increase thread priority as necessary.  This is done
    # to ensure that the encoding and sled generation get
    # enough time slices from the ruby thread scheduler.
    priority = Thread.current.priority

    if (priority == 0)
      Thread.current.priority = 1
    end

    begin
      # First, validate
      payload_instance.validate()

      # Generate the raw version of the payload first
      generate_raw() if self.raw.nil?

      # Encode the payload
      encode()

      # Build the NOP sled
      generate_sled()

      # Finally, set the complete payload definition
      self.encoded = (self.nop_sled || '') + self.encoded
    ensure
      # Restore the thread priority
      Thread.current.priority = priority
    end

    # Return the complete payload
    return encoded
  end

  #
  # Generates the raw payload from the payload instance.  This populates the
  # {#raw} attribute.
  #
  # @return [String] The raw, unencoded payload.
  def generate_raw
    self.raw = (reqs['Prepend'] || '') + payload_instance.generate + (reqs['Append'] || '')

    # If an encapsulation routine was supplied, then we should call it so
    # that we can get the real raw payload.
    if reqs['EncapsulationRoutine']
      self.raw = reqs['EncapsulationRoutine'].call(reqs, raw)
    end
  end

  #
  # Scans for a compatible encoder using ranked precedence and populates the
  # encoded attribute.
  #
  def encode
    # If the exploit has bad characters, we need to run the list of encoders
    # in ranked precedence and try to encode without them.
    if reqs['BadChars'].present? or reqs['Encoder'] or reqs['ForceEncode']
      cache_encoder_instances = payload_instance.compatible_cache_encoder_instances

      # Fix encoding issue
      if reqs['Encoder']
        reqs['Encoder'] = reqs['Encoder'].encode(framework.encoders.keys[0].encoding)
      end

      required_encoder_reference_name = reqs['Encoder']

      if required_encoder_reference_name.present?
        ActiveRecord::Base.connection_pool.with_connection do
          cache_encoder_instances = Mdm::Module::Instance.with_module_type(
              'encoder'
          ).joins(
              :module_class
          ).where(
              Mdm::Module::Class.arel_table[:reference_name].eq(required_encoder_reference_name)
          )

          unless cache_encoder_instances.exists?
            wlog("#{payload_instance.reference_name}: Failed to find preferred encoder #{required_encoder_reference_name}")

            raise NoEncodersSucceededError, "Failed to find preferred encoder #{required_encoder_reference_name}"
          end
        end
      end

      # include module_class association as it will be accessed immediately to create the in-memory instance.
      cache_encoder_instances = cache_encoder_instances.includes(:module_class)

      # Use find_each to return found `Mdm::Module::Instance` in batches to better handle large number of modules.
      cache_encoder_instances.each { |cache_encoder_instance|
        cache_encoder_class = cache_encoder_instance.module_class
        self.encoder = framework.modules.create_from_module_class(cache_encoder_class)
        self.encoded = nil

        # If there is an encoder type restriction, check to see if this
        # encoder matches with what we're searching for.
        required_encoder_type = reqs['EncoderType']

        if required_encoder_type
          allowed_encoder_types = encoder.encoder_type.split /\s+/

          unless allowed_encoder_types.include?(required_encoder_type)
            wlog(
                "#{payload_instance.reference_name}: " \
                  "Encoder #{encoder.reference_name} is not a compatible encoder type: " \
                  "#{required_encoder_type} is not in #{self.encoder.encoder_type}",
                'core',
                LEV_1
            )

            next
          end
        end

        # If the exploit did not explicitly request a kind of encoder and
        # the current encoder has a manual ranking, then it should not be
        # considered as a valid encoder.  A manual ranking tells the
        # framework that an encoder must be explicitly defined as the
        # encoder of choice for an exploit.
        if required_encoder_type.nil? &&
            reqs['Encoder'].nil? &&
            self.encoder.rank_name == 'Manual'
          wlog(
              "#{payload_instance.reference_name}: " \
              "Encoder #{encoder.reference_name} is manual ranked and was not defined as a preferred encoder.",
              'core',
              LEV_1
          )

          next
        end

        # Import the data_store from payload (and likely exploit by proxy)
        self.encoder.share_data_store(payload_instance.data_store)

        # If we have any encoder options, import them into the data_store
        # of the encoder.
        required_encoder_options = reqs['EncoderOptions']

        if required_encoder_options
          self.encoder.data_store.import_options_from_hash(required_encoder_options)
        end

        # Validate the encoder to make sure it's properly initialized.
        begin
          self.encoder.validate
        rescue ::Exception => exception
          wlog(
              "#{payload_instance.reference_name}: Failed to validate encoder #{encoder.reference_name}: #{exception}",
              'core',
              LEV_1
          )

          next
        end

        eout = self.raw.dup

        next_encoder = false

        # Try encoding with the current encoder
        #
        # NOTE: Using more than one iteration may cause successive iterations to switch
        # to using a different encoder.
        #
        1.upto(self.iterations) do |iter|
          err_start = "#{payload_instance.reference_name}: iteration #{iter}"

          begin
            eout = self.encoder.encode(eout, reqs['BadChars'], nil, payload_instance.platform_list)
          rescue EncodingError => encoding_error
            wlog("#{err_start}: Encoder #{encoder.reference_name} failed: #{encoding_error}", 'core', LEV_1)
            dlog("#{err_start}: Call stack\n#{encoding_error.backtrace.join("\n")}", 'core', LEV_3)
            next_encoder = true
            break

          rescue ::Exception => exception
            elog("#{err_start}: Broken encoder #{encoder.reference_name}: #{exception}", 'core', LEV_0)
            dlog("#{err_start}: Call stack\n#{exception.backtrace.join("\n")}", 'core', LEV_1)
            next_encoder = true
            break
          end

          # Get the minimum number of nops to use
          min = (reqs['MinNops'] || 0).to_i
          min = 0 if reqs['DisableNops']

          # Check to see if we have enough room for the minimum requirements
          required_space = reqs['Space']

          if required_space && required_space < (eout.length + min)
            wlog("#{err_start}: Encoded payload version is too large with encoder #{encoder.reference_name}",
              'core', LEV_1)
            next_encoder = true

            # break iterations loop for this encoder, go to next encoder in outer loop
            break
          end

          ilog(
              "#{err_start}: Successfully encoded with encoder #{encoder.reference_name} (size is #{eout.length})",
              'core',
              LEV_0
          )
        end

        # required space was exceeded by current encoder, so try the next encoder to see if it can fit
        next if next_encoder

        self.encoded = eout

        break
      }

      if self.encoded.nil?
        self.encoder = nil

        raise NoEncodersSucceededError, "#{payload_instance.reference_name}: All encoders failed to encode."
      end

    # If there are no bad characters, then the raw is the same as the
    # encoded
    else
      self.encoded = raw
    end

    # Prefix the prepend encoder value
    self.encoded = (reqs['PrependEncoder'] || '') + self.encoded
  end

  #
  # Construct a NOP sled if necessary
  #
  def generate_sled
    min   = reqs['MinNops'] || 0
    space = reqs['Space']

    self.nop_sled_size = min

    # Calculate the number of NOPs to pad out the buffer with based on the
    # requirements.  If there was a space requirement, check to see if
    # there's any room at all left for a sled.
    if ((space) and
       (space > encoded.length))
      self.nop_sled_size = reqs['Space'] - self.encoded.length
    end

    # If the maximum number of NOPs has been exceeded, wrap it back down.
    if ((reqs['MaxNops']) and
       (reqs['MaxNops'] < self.nop_sled_size))
      self.nop_sled_size = reqs['MaxNops']
    end

    # Check for the DisableNops setting
    self.nop_sled_size = 0 if reqs['DisableNops']

    # Now construct the actual sled
    if (self.nop_sled_size > 0)
      cache_nop_instances = payload_instance.compatible_cache_nop_instances

      required_nop_reference_name = reqs['Nop']

      if required_nop_reference_name.present?
        ActiveRecord::Base.connection_pool.with_connection do
          module_class_reference_name = Mdm::Module::Class.arel_table[:reference_name]

          required_cache_nop_instances = Mdm::Module::Instance.with_module_type(
              'nop'
          ).joins(
              :module_class
          ).where(
              module_class_reference_name.eq(required_nop_reference_name)
          )

          # exclude required_nop_reference_name from the list of all nop instance so it isn't tried twice
          cache_nop_instances = cache_nop_instances.joins(
              :module_class
          ).where(
              module_class_reference_name.not_eq(required_nop_reference_name)
          )

          unless required_cache_nop_instances.exist?
            wlog("#{payload_instance.reference_name}: Failed to find preferred nop #{required_nop_reference_name}")
          end
        end

        relations = [required_cache_nop_instances, cache_nop_instances]
      else
        relations = [cache_nop_instances]
      end

      relations.each do |relation|
        # include module_class as it will be accessed immediately to instantiate the in-memory instance
        relation = relation.includes(:module_class)

        relation.each do |cache_nop_instance|
          cache_nop_class = cache_nop_instance.module_class
          self.nop = framework.modules.create_from_module_class(cache_nop_class)

          # Propagate options from the payload and possibly exploit
          self.nop.share_data_store(payload_instance.data_store)

          # The list of save registers
          save_regs = (reqs['SaveRegisters'] || []) + (payload_instance.save_registers || [])

          if save_regs.empty?
            save_regs = nil
          end

          begin
            nop.copy_ui(payload_instance)

            self.nop_sled = nop.generate_sled(self.nop_sled_size,
                                              'BadChars'      => reqs['BadChars'],
                                              'SaveRegisters' => save_regs)
          rescue => error
            dlog(
                "#{payload_instance.refname}: " \
                "Nop generator #{nop.refname} failed to generate sled for payload: #{error}",
                'core',
                LEV_1
            )

            next
          else
            break
          end
        end
      end

      unless self.nop_sled
        raise NoNopsSucceededError,
              "#{payload_instance.reference_name}: All NOP generators failed to construct sled for."
      end
    else
      self.nop_sled = ''
    end

    return self.nop_sled
  end


  #
  # Convert the payload to an executable appropriate for its arch and
  # platform.
  #
  # +opts+ are passed directly to +Msf::Util::EXE.to_executable+
  #
  # see +Msf::Exploit::EXE+
  #
  def encoded_exe(opts={})
    # Ensure arch and platform are in the format that to_executable expects
    if opts[:arch] and not opts[:arch].kind_of? Array
      opts[:arch] = [ opts[:arch] ]
    end
    if (opts[:platform].kind_of? Msf::Module::PlatformList)
      opts[:platform] = opts[:platform].platforms
    end

    emod = payload_instance.exploit_instance if payload_instance.respond_to? :exploit_instance

    if emod
      if (emod.data_store["EXE::Custom"] and emod.respond_to? :get_custom_exe)
        return emod.get_custom_exe
      end
      # This is a little ghetto, grabbing data_store options from the
      # associated exploit, but it doesn't really make sense for the
      # payload to have exe options if the exploit doesn't need an exe.
      # Msf::Util::EXE chooses reasonable defaults if these aren't given,
      # so it's not that big of an issue.
      opts.merge!({
        :template_path => emod.data_store['EXE::Path'],
        :template => emod.data_store['EXE::Template'],
        :inject => emod.data_store['EXE::Inject'],
        :fallback => emod.data_store['EXE::FallBack'],
        :sub_method => emod.data_store['EXE::OldMethod']
      })
      # Prefer the target's platform/architecture information, but use
      # the exploit module's if no target specific information exists.
      opts[:platform] ||= emod.target_platform  if emod.respond_to? :target_platform
      opts[:platform] ||= emod.platform         if emod.respond_to? :platform
      opts[:arch] ||= emod.target_arch          if emod.respond_to? :target_arch
      opts[:arch] ||= emod.arch                 if emod.respond_to? :arch
    end
    # Lastly, try the payload's. This always happens if we don't have an
    # associated exploit module.
    opts[:platform] ||= payload_instance.platform if payload_instance.respond_to? :platform
    opts[:arch] ||= payload_instance.arch         if payload_instance.respond_to? :arch

    Msf::Util::EXE.to_executable(
        opts.merge(
            architecture_abbreviations: opts[:arch],
            code: encoded,
            framework: framework,
            platforms: opts[:platform]
        )
    )
  end

  #
  # Generate a jar file containing the encoded payload.
  #
  # Uses the payload's +generate_jar+ method if it is implemented (Java
  # payloads should all have it).  Otherwise, converts the payload to an
  # executable and uses Msf::Util::EXE.to_jar to create a jar file that dumps
  # the exe out to a random file name in the system's temporary directory and
  # executes it.
  #
  def encoded_jar(opts={})
    return payload_instance.generate_jar(opts) if payload_instance.respond_to? :generate_jar

    opts[:spawn] ||= payload_instance.data_store["Spawn"]

    Msf::Util::EXE.to_jar(encoded_exe(opts), opts)
  end

  #
  # Similar to +encoded_jar+ but builds a web archive for use in servlet
  # containers such as Tomcat.
  #
  def encoded_war(opts={})
    return payload_instance.generate_war(opts) if payload_instance.respond_to? :generate_war

    Msf::Util::EXE.to_jsp_war(encoded_exe(opts), opts)
  end

  #
  # The raw version of the payload
  #
  attr_reader :raw
  #
  # The encoded version of the raw payload plus the NOP sled
  # if one was generated.
  #
  attr_reader :encoded
  #
  # The size of the NOP sled
  #
  attr_reader :nop_sled_size
  #
  # The NOP sled itself
  #
  attr_reader :nop_sled
  #
  # The encoder that was used
  #
  attr_reader :encoder
  #
  # The NOP generator that was used
  #
  attr_reader :nop
  #
  # The number of encoding iterations used
  #
  attr_reader :iterations

protected

  attr_writer :raw # :nodoc:
  attr_writer :encoded # :nodoc:
  attr_writer :nop_sled_size # :nodoc:
  attr_writer :nop_sled # :nodoc:
  attr_writer :payload # :nodoc:
  attr_writer :encoder # :nodoc:
  attr_writer :nop # :nodoc:
  attr_writer :iterations # :nodoc:

  #
  # The requirements used for generation
  #
  attr_accessor :reqs

end

end
