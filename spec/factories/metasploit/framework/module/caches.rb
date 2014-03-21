FactoryGirl.define do
  factory :metasploit_framework_module_cache,
          class: Metasploit::Framework::Module::Cache,
          traits: [
              :metasploit_model_base
          ] do
    association :universal_module_instance_creator, factory: :metasploit_framework_module_instance_creator_universal
  end
end