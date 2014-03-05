FactoryGirl.define do
  klass = Msf::Simple::Framework

  factory :msf_simple_framework,
          class: klass,
          traits: [
              :metasploit_model_base,
              :msf_framework_attributes
          ] do
    # dont' call a proc by default
    on_create_proc { nil }
    # don't load any module paths so we can just load the module under test and save time
    defer_module_loads { true }

    initialize_with {
      # anything besides new must be called explicitly on the Class
      klass.create(
          'DeferModuleLoads' => defer_module_loads,
          database_disabled: database_disabled,
          module_types: module_types,
          pathnames: pathnames,
          'OnCreateProc' => on_create_proc
      )
    }
  end
end