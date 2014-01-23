# Modifies {#eager_load!} so that it only requires dependencies in `app` and `lib/metasploit` instead of all of `lib` as
# older code is not safe to eagerly load.
class Metasploit::Framework::Configuration::Autoload < Metasploit::Model::Configuration::Autoload
  #
  # Methods
  #

  # Eager loads all rb files under `app` and `lib/metasploit`, but skips those under other `lib` subdirectories.
  #
  # @return [void]
  def eager_load!
    # sort to favor app over lib since it is assumed that app/models will define classes and lib will define modules
    # included in those classes that are defined under the class namespaces, so the class needs to be required first
    all_paths.sort.each do |load_path|
      matcher = /\A#{Regexp.escape(load_path)}\/(.*)\.rb\Z/

      Dir.glob("#{load_path}/**/*.rb").sort.each do |file|
        require_path = file.sub(matcher, '\1')

        # skip paths that aren't eager-load safe
        unless load_path.end_with?('lib') && !require_path.start_with?('metasploit')
          require_dependency require_path
        end
      end
    end
  end
end