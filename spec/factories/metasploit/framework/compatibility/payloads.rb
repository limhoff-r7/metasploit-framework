FactoryGirl.define do
  factory :metasploit_framework_compatibility_payload,
          class: Metasploit::Framework::Compatibility::Payload,
          traits: [
              :metasploit_model_base
          ] do
    association :exploit_instance, factory: :msf_exploit
  end
end