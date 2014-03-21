FactoryGirl.define do
  factory :metasploit_framework_module_instance_payload_actual_compatibility_payload,
          class: Metasploit::Framework::Module::Instance::Payload::Actual::Compatibility::Payload,
          parent: :metasploit_framework_compatibility_payload do
    ignore do
      architecture_abbreviation_count { 1 }
      # ensure that exploit_instance and universal_module_instance_creator share the same framework
      framework { FactoryGirl.create(:msf_simple_framework) }
      platform_fully_qualified_name_count { 1 }
    end

    architecture_abbreviations {
      Array.new(architecture_abbreviation_count) {
        generate :metasploit_model_architecture_abbreviation
      }
    }

    exploit_instance {
      FactoryGirl.create(:msf_exploit, framework: framework)
    }

    platform_fully_qualified_names {
      Array.new(platform_fully_qualified_name_count) {
        platform = generate :mdm_platform
        platform.fully_qualified_name
      }
    }

    universal_module_instance_creator { framework.modules }
  end
end