FactoryGirl.define do
  factory :metasploit_framework_framework_pathnames,
          class: Metasploit::Framework::Framework::Pathnames do
    ignore do
      # root is ignored because it's used in initialize_with and not meant to be written as an attribute
      root { generate :metasploit_framework_framework_pathnames_root }
    end

    initialize_with {
      # Metasploit::Frameowkr::Framework::Pathnames is frozen at the end of #initialize, so everything has to be passed
      # to new
      new(root: root)
    }
  end

  sequence :metasploit_framework_framework_pathnames_root do |n|
    Metasploit::Model::Spec.temporary_pathname.join(
        'metasploit',
        'framework',
        'framework',
        'pathnames',
        'roots',
        n.to_s
    )
  end
end