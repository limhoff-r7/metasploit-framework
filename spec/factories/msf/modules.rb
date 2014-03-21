FactoryGirl.define do
  factory :msf_module,
          class: Msf::Module,
          traits: [
              :metasploit_model_base
          ] do
    association :framework, factory: :msf_simple_framework
  end
end