# -*- coding: binary -*-

module Msf::Session

module Scriptable

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    # Pathnames that will be checked for a script, in order of precedence.  Scripts under {Msf::Framework#pathnames}
    # {Metasploit::Framework::Framework::Pathnames#scripts} are favored over those under
    # {Metasploit::Framework.pathnames}, so users can override the installed scripts.
    #
    # @param options [Hash{Symbol => String,Msf::Framework}]
    # @option options [String] :basename basename of the script with or without file extension.
    # @option options :framework (see #scripts_pathnames)
    # @yield [pathname] Block takes potential pathnames to search for the script.
    # @yieldparam pathname A potential pathname for the script.  It should be checked with `Pathname#exist?`.
    # @yieldreturn [void]
    # @return [void]
    # @raise [KeyError] unless :basename is given.
    # @raise (see #scripts_pathnames)
    def script_pathnames(options={})
      options.assert_valid_keys(:basename, :framework)

      basename = options.fetch(:basename)

      unless block_given?
        enum_for(__method__, options)
      else
        scripts_pathnames(framework: options[:framework]) do |scripts_pathname|
          ['', '.rb'].each do |extension|
            yield scripts_pathname.join("#{basename}#{extension}")
          end
        end
      end
    end

    # The directories under {#script_pathnames} can be found.  {Metasploit::Framework::Framework::Pathnames#scripts} are
    # favored over those under {Metasploit::Framework::Configuration::Pathnames#scripts}, so users can override the
    # installed scripts.
    #
    # @param options [Hash{Symbol => Msf::Framework}]
    # @option options [Msf::Framework, #pathnames] :framework Framework whose {Msf::Framework#pathnames} to use to look
    #   for framework-specific implementations of scripts.  If `nil`, then only installation scripts pathname will be
    #   returned.
    # @yield [pathname]
    # @yieldparam pathname [Pathname] directory under which a script could be found.
    # @yieldreturn [void]
    # @return [void]
    def scripts_pathnames(options={})
      options.assert_valid_keys(:framework)

      pathnames_parents = []

      framework = options[:framework]

      if framework
        pathnames_parents << framework
      end

      pathnames_parents << Metasploit::Framework

      unless block_given?
        enum_for(__method__, options)
      else
        pathnames_parents.each do |pathnames_parent|
          yield pathnames_parent.pathnames.scripts.join(type)
        end
      end
    end

    # Finds path to the script.  Scripts under {Msf::Framework#pathnames}
    # {Metasploit::Framework::Framework::Pathnames#scripts} are favored over those under
    # {Metasploit::Framework.pathnames}, so users can override the installed scripts.
    #
    # @param (see #script_pathnames)
    # @option (see #script_pathnames)
    # @return [Pathname] if script is found.
    # @return [nil] if script is not found.
    # @raise (see #script_pathnames)
    def find_script_pathname(options={})
      script_pathnames(options).find(&:exist?)
    end
  end

  #
  # Override
  #
  def execute_file(path, args)
    raise NotImplementedError
  end

  #
  # Executes the supplied script or Post module with arguments +args+
  #
  # Will search the script path.
  #
  def execute_script(script_name, *args)
    cache_module_class = Mdm::Module::Class.where(full_name: script_name, module_type: 'post').first

    if cache_module_class
      post_instance = framework.modules.create_from_module_class(cache_module_class)

      if post_instance
        opts = { 'SESSION' => self.sid }

        args.each do |arg|
          k,v = arg.split("=", 2)
          opts[k] = v
        end

        post_instance.run_simple(
            'LocalInput'  => self.user_input,
            'LocalOutput' => self.user_output,
            'Options'     => opts
        )
      else
        print_error(
            "#{script_name} is a post module full name, but it could not be instantiated.  " \
            "Consult #{framework.pathnames.logs.join('framework.log')} for more details"
        )

        true
      end
    else
      pathname = self.class.find_script_pathname(basename: script_name, framework: framework)

      unless pathname
        print_error("The specified script could not be found: #{script_name}")

        true
      else
        framework.events.on_session_script_run(self, pathname)
        execute_file(pathname, args)
      end
    end
  end
end

end

