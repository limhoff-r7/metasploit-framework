FactoryGirl.define do
  factory :metasploit_framework_module_cache,
          class: Metasploit::Framework::Module::Cache,
          traits: [
              :metasploit_model_base
          ] do
    association :framework, factory: :msf_simple_framework
  end
end