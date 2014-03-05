FactoryGirl.define do
  factory :msf_framework,
          class: Msf::Framework,
          traits: [
              :metasploit_model_base,
              :msf_framework_attributes
          ] do
    initialize_with {
      # pathnames does not have a writer, so have to passed to new
      new(pathnames: pathnames)
    }
  end

  trait :msf_framework_attributes do
    ignore do
      # pathnames is ignored because it is used in initialize_with and not meant to be written as an attribute
      pathnames { build(:metasploit_framework_framework_pathnames) }
    end

    module_types { Metasploit::Model::Module::Type::ALL }
  end
end