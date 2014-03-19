FactoryGirl.define do
  factory :msf_module_manager,
          class: Msf::ModuleManager,
          traits: [
              :metasploit_model_base
          ] do
    #
    # Associations
    #

    association :framework, factory: :msf_simple_framework
  end
end