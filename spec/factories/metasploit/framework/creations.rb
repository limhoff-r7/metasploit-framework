FactoryGirl.define do
  factory :metasploit_framework_creation,
          class: Metasploit::Framework::Creation,
          traits: [
              :metasploit_model_base
          ]
end