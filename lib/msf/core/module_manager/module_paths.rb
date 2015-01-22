##
#
# Module path management
#
##
module Msf::ModuleManager::ModulePaths
  #
  # Adds a path to be searched for new modules.
  #
  def add_module_path(path)
    npaths = []

    if path =~ /\.fastlib$/
      unless ::File.exist?(path)
        raise RuntimeError, "The path supplied does not exist", caller
      end
      npaths << ::File.expand_path(path)
    else
      path.sub!(/#{File::SEPARATOR}$/, '')

      # Make the path completely canonical
      path = Pathname.new(File.expand_path(path))

      # Make sure the path is a valid directory
      unless path.directory?
        raise RuntimeError, "The path supplied is not a valid directory.", caller
      end

      # Now that we've confirmed it exists, get the full, cononical path
      path    = ::File.expand_path(path)
      npaths << path

      # Identify any fastlib archives inside of this path
      Dir["#{path}/**/*.fastlib"].each do |fp|
        npaths << fp
      end
    end

    # Update the module paths appropriately
    self.module_paths = (module_paths + npaths).flatten.uniq

    # Load all of the modules from the new paths
    counts = nil
    npaths.each { |d|
      counts = load_modules(d, false)
    }

    return counts
  end

  #
  # Removes a path from which to search for modules.
  #
  def remove_module_path(path)
    module_paths.delete(path)
    module_paths.delete(::File.expand_path(path))
  end

  attr_accessor :module_paths # :nodoc:
end