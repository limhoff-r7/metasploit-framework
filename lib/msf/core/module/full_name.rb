require 'metasploit/framework/deprecation'

# Names that derive from `Mdm::Module::Class#full_name`.
module Msf::Module::FullName
  extend ActiveSupport::Concern

  module ClassMethods
    # @!method fullname
    #   (see #full_name)
    #   @deprecated Use {#full_name}.
    #
    # @!method refname
    #   (see #reference_name)
    #    @deprecated Use {#reference_name}
    #
    # @!method shortname
    #   (see #short_name)
    #   @deprecated Use {#short_name}
    Metasploit::Framework::Deprecation.rename_methods(
        self,
        fullname: :full_name,
        refname: :reference_name,
        shortname: :short_name
    )

    # The module's full name, including its module_type and {#reference_name}.
    #
    # @return [String] '<module_type>/<{#reference_name}>'.
    def full_name
      # cache the value to limit the trips to the database
      @full_name ||= module_class.full_name
    end

    # The name of the module scoped to the module type.
    #
    # @return [String]
    def reference_name
      # cache the value to limit the trips to the database
      @reference_name ||= module_class.reference_name
    end

    # The last name in the {#reference_name}.  Use along with the module type in the console and other UI locations
    # where the {#full_name} would be too long.
    #
    # @return [String]
    def short_name
      @short_name ||= reference_name.split('/')[-1]
    end
  end

  #
  # Instance Methods
  #

  # @!method full_name
  #   (see Msf::Module::FullName::ClassMethods#full_name)
  #
  # @!method reference_name
  #   (see Msf::Module::FullName::ClassMethods#reference_name)
  #
  # @!method short_name
  #   (see Msf::Module::FullName::ClassMethods#short_name)
  delegate :full_name,
           :reference_name,
           :short_name,
           to: 'self.class'

  # @!method fullname
  #   (see #full_name)
  #   @deprecated Use {#full_name}.
  #
  # @!method refname
  #   (see #reference_name)
  #    @deprecated Use {#reference_name}
  #
  # @!method shortname
  #   (see #short_name)
  #   @deprecated Use {#short_name}
  Metasploit::Framework::Deprecation.rename_methods(
      self,
      fullname: :full_name,
      refname: :reference_name,
      shortname: :short_name
  )
end
