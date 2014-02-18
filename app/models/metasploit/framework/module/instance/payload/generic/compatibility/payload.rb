class Metasploit::Framework::Module::Instance::Payload::Generic::Compatibility::Payload < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] handler_module
  #   @return [Module]
  attr_accessor :handler_module

  # @!attribute [rw] parent
  #   @return [#each_compatible_instance]
  attr_accessor :parent

  # @!attribute [rw] payload_type
  #   @return [String]
  attr_accessor :payload_type

  # @!attribute [rw] session_class
  #   @return [Class<Msf::Session>]
  attr_accessor :session_class

  #
  # Validations
  #

  validates :payload_type,
            inclusion: {
                in: Metasploit::Model::Module::Class::PAYLOAD_TYPES
            }

  def each_compatible_instance
    unless block_given?
      enum_for(__method__)
    else
      parent.each_compatible_instance(include_generics: false) do |parent_compatible_instance|
        if payload_instance_compatible?(parent_compatible_instance)
          yield parent_compatible_instance
        end
      end
    end
  end

  private

  # Whether the :candidate is compatible with :attribute.
  #
  # @return [true] if :candidate and :attribute are both `nil`.
  # @return [true] if :candidate is not `nil` and :attribute is not `nil` and
  #   :attribute is in `Module#ancestors` of :candidate
  # @return [false] if :candidate is `nil` and :attribute is not `nil` or vice-versa.
  # @return [false] if :candidate is not `nil` and :attribute is not `nil`, but :attribute is not in `Module#ancestors` of
  #   :candidate.
  def compatible_ancestors?(options={})
    options.assert_valid_keys(:attribute, :candidate)

    attribute = options[:attribute]
    candidate = options[:candidate]

    if attribute
      if candidate
        compatible = candidate.ancestors.include? attribute
      else
        # the generic payload is looking for an actual payload with the attribute, but payload_instance doesn't have
        # one, so it's incompatible
        compatible = false
      end
    elsif candidate
      # the generic payload is looking for an actual payload without the attribute, but candidate is not nil, so it's
      # incompatible
      compatible = false
    else
      # both have no value, so they are compatible.
      compatible = true
    end

    compatible
  end

  def handler_module_compatible?(payload_instance)
    compatible_ancestors?(
        attribute: handler_module,
        candidate: payload_instance.class.ancestor_handler_module
    )
  end

  # Whether the `payload_instance` has (1) {Metasploit::Framework::Module::Class::Handler#ancestor_handler_module}
  # compatible with {#handler_module}; (2) {Metasploit::Framework::Module::Class::MetasploitClass#module_class}
  # `Mdm::Module::Class#payload_type` equal to {#payload_type}; and (3) {Msf::Payload#session_class} compatible with
  # {#session_class}.
  def payload_instance_compatible?(payload_instance)
    [:handler_module_compatible?, :session_class_compatible?, :payload_type_compatible?].all? { |compatible|
      send(compatible, payload_instance)
    }
  end

  def payload_type_compatible?(payload_instance)
    payload_instance.class.module_class.payload_type == payload_type
  end

  def session_class_compatible?(payload_instance)
    compatible_ancestors?(
        attribute: session_class,
        candidate: payload_instance.session_class
    )
  end
end