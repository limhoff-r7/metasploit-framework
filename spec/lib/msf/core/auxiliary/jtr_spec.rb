require 'spec_helper'

describe Msf::Auxiliary::JohnTheRipper do
  include_context 'database cleaner'
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Simple::Framework'

  #
  # methods
  #

  # @note Should be called prior to `framework.moduls.create_from_module_class` or any other method which loads the
  #   ancestors of `cache_auxiliary_instance`.
  #
  # Adds search pathname to template that will add `include Msf::Auxiliary::JohnTheRipper` to the auxiliary class.
  #
  # @return [void]
  def write_include
    template = Metasploit::Model::Module::Instance::Spec::Template.new(module_instance: cache_auxiliary_instance)

    template.class_template.ancestor_templates.each do |ancestor_template|
      ancestor_template.search_pathnames.unshift(
          Pathname.new('auxiliary/john_the_ripper/instances')
      )
    end

    template.valid!
    template.write
  end

  #
  # lets
  #

  let(:auxiliary_instance) do
    write_include

    framework.modules.create_from_module_class(cache_auxiliary_instance.module_class)
  end

  let(:cache_auxiliary_instance) do
    FactoryGirl.create(
        :mdm_module_instance,
        module_class: cache_auxiliary_class
    )
  end

  let(:cache_auxiliary_class) do
    FactoryGirl.create(
        :mdm_module_class,
        module_type: 'auxiliary'
    )
  end

  it_should_behave_like 'Msf::Auxiliary::JohnTheRipper'
end