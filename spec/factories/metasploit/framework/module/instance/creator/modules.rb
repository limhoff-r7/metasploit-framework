FactoryGirl.define do
  factory :metasploit_framework_module_instance_creator_universal,
          class: Metasploit::Framework::Module::Instance::Creator::Universal,
          traits: [
              :metasploit_model_base
          ] do
    #
    # Associations
    #

    association :framework, factory: :msf_simple_framework
  end
end