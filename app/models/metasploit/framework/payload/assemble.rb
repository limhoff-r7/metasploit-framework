class Metasploit::Framework::Payload::Assemble < Metasploit::Model::Base
  # create the mutex declaratively so there isn't a race condition on the first use in {cache_shellcode}.
  @entry_by_cpu_class_by_assembly_without_raw_mutex = Mutex.new

  #
  # CONSTANTS
  #

  CPU_CLASS_BY_ARCHITECTURE_ABBREVIATION = {
      ARCH_ARMLE => Metasm::ARM,
      ARCH_PPC => Metasm::PowerPC,
      ARCH_X86 => Metasm::Ia32,
      ARCH_X86_64 => Metasm::X86_64
  }

  #
  # Attributes
  #

  # @!attribute [rw] assembly
  #   The assembly language source code.
  #
  #   @return [String]
  attr_accessor :assembly

  # @!attribute [rw] offset_relative_address_and_type_by_name
  #   @return offset_relative_address_and_type_by_name [Hash{String => Array<(Integer, String)>}]
  attr_accessor :offset_relative_address_and_type_by_name

  # @!attribute [rw] payload_instance
  #   @return [Msf::Payload]
  attr_accessor :payload_instance

  #
  # Validations
  #

  validates :architecture_abbreviations,
            length: {
                is: 1
            }
  validates :assembly,
            presence: true
  validates :cpu_class,
            presence: true
  validates :payload_instance,
            presence: true

  #
  # Methods
  #

  delegate :architecture_abbreviations,
           allow_nil: true,
           to: :payload_instance

  # @return [Metasploit::Framework::Payload::Assembled]
  def assembled
    unless instance_variable_defined? :@assembled
      shellcode = self.class.cache_shellcode(
          assembly_without_raw: assembly_without_raw,
          cpu_class: cpu_class) {
        Metasm::Shellcode.assemble(cpu, assembly_without_raw).encoded
      }

      assembled = Metasploit::Framework::Payload::Assembled.new(data: shellcode.data)

      offset_relative_address_and_type_by_name.each do |name, (relative_address, type)|
        shellcode_relative_address = shellcode.offset_of_reloc(name) || relative_address
        relative_address_and_type = [shellcode_relative_address, type]
        assembled.offset_relative_address_and_type_by_name[name] = relative_address_and_type
      end

      assembled.valid!

      @assembled = assembled
    end

    @assembled
  end

  def self.entry_by_cpu_class_by_assembly_without_raw
    @entry_by_cpu_class_by_assembly_without_raw ||= Hash.new { |hash, assembly_without_raw|
      hash[assembly_without_raw] = {}
    }
  end

  # Caches the {#shellcode} for a given combination of {#assembly_without_raw} and {#cpu_class}.  Cache access is
  # synchronized, so it should be thread-safe.
  #
  # @param options [Hash{Symbol => Object}] The arguments to {Metasm::Shellcode.assemble} that produced the cached
  #   shellcode.
  # @option options [String] :assembly_without_raw {#assembly_without_raw}
  # @option options [Class] :cpu_class {#cpu_class}
  # @yield assemble the encoded shellcode data for the given options.
  # @yieldreturn [Metasm::EncodedData] the encoded, assembled shellcode for the given options.
  # @return [Metasm::EncodedData]
  def self.cache_shellcode(options={})
    options.assert_valid_keys(:assembly_without_raw, :cpu_class)

    assembly_without_raw = options[:assembly_without_raw]
    cpu_class = options[:cpu_class]
    shellcode = nil

    @entry_by_cpu_class_by_assembly_without_raw_mutex.synchronize do
      entry_by_cpu_class = entry_by_cpu_class_by_assembly_without_raw[assembly_without_raw]
      entry = entry_by_cpu_class[cpu_class]

      if entry.nil?
        entry_mutex = Mutex.new

        # lock the entry_mutex prior to releasing the parent lock so that the next thread that sees the
        # entry_mutex in the cache will wait for this thread to finish generating from yield
        entry_mutex.synchronize do
          entry_by_cpu_class[cpu_class] = entry_mutex

          # unlock parent lock so that other cache key can be generated
          @entry_by_cpu_class_by_assembly_without_raw_mutex.unlock

          begin
            entry = yield
          rescue => error
            entry = error

            # reraise error, which will be raised after ensure adds the error to the cache for the other threads to
            # reraise.
            raise error
          else
            # make sure the {Metasm::EncodedData} and its {Metasm::EncodedData#data} cannot be modified, such as by
            # {Msf::Payload#substitute_vars} as that would invalidate the cache.
            shellcode = IceNine.deep_freeze(entry)
          ensure
            # Require acquire parent lock for write back to cache
            # End of parent synchronize block will unlock parent lock
            @entry_by_cpu_class_by_assembly_without_raw_mutex.lock

            entry_by_cpu_class[cpu_class] = entry
          end
        end
      elsif entry.is_a? Mutex
        entry_mutex = entry

        if entry_mutex.locked?
          # if this thread can't get the child lock, then give up our hold on the parent lock while this thread waits
          # for the child lock so that other cache entries can be generated
          @entry_by_cpu_class_by_assembly_without_raw_mutex.unlock
        end

        # attempt to lock the child lock, which will wait until the generating thread calling yield finishes
        entry_mutex.synchronize do
          # require parent lock to read shellcode_by_cpu_class
          @entry_by_cpu_class_by_assembly_without_raw_mutex.lock

          entry = entry_by_cpu_class[cpu_class]

          # if entry is an error then the generating thread experienced an error and it should be assumed that all
          # all threads would raise that same error if they attempted to generate the code
          if entry.is_a? Error
            error = entry

            raise error
          else
            shellcode = entry
          end
        end
      else
        shellcode = entry
      end
    end

    shellcode
  end

  private

  def architecture_abbreviation
    architecture_abbreviations.first
  end

  # {#assembly} with all 'RAW' substitutions from {#offset_relative_address_and_type_by_name} already
  # made.
  #
  # @return [String]
  def assembly_without_raw
    unless instance_variable_defined? :@assembly_without_raw
      assembly_without_raw = assembly

      offset_relative_address_and_type_by_name.each { |name, (_relative_address, type)|
        if type == 'RAW'
          assembly_without_raw = assembly_without_raw.gsub(/#{name}/) { data_store[name] }
        end
      }

      @assembly_without_raw = assembly_without_raw
    end

    @assembly_without_raw
  end

  def cpu
    @cpu ||= cpu_class.new
  end

  def cpu_class
    @cpu_class ||= CPU_CLASS_BY_ARCHITECTURE_ABBREVIATION[architecture_abbreviation]
  end
end