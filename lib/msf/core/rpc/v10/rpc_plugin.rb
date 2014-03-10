# -*- coding: binary -*-
module Msf
module RPC
class RPC_Plugin < RPC_Base

  def rpc_load(path, xopts = {})

    opts  = {}

    xopts.each do |k,v|
      if k.class == String
        opts[k.to_sym] = v
      end
    end

    if (path !~ /#{File::SEPARATOR}/)
      plugin_file_name = path
      path = nil

      pathnames_parents = [
          framework,
          Metasploit::Framework
      ]

      pathnames_parents.each do |pathnames_parent|
        plugins = pathnames_parent.pathnames.plugins
        pathname = plugins.join("#{plugin_file_name}.rb")

        if pathname.exist?
          # Msf::PluginManager#load take a path without a file extension
          path = plugins.join(plugin_file_name).to_path
        end
      end
    end

    result = 'failure'

    if path
      begin
        plugin_instance = framework.plugins.load(path, opts)
      rescue ::Exception => exception
        src = 'core'
        level = 0
        elog("Error loading plugin #{path}: #{exception}\n\n#{exception.backtrace.join("\n")}", src, level, caller)
      else
        if plugin_instance
          result = 'success'
        end
      end
    end


    { 'result' => result }
  end

  def rpc_unload(name)
    self.framework.plugins.each { |plugin|
      # Unload the plugin if it matches the name we're searching for
      if (plugin.name == name)
        self.framework.plugins.unload(plugin)
        return 	{ "result" => "success" }
      end
    }
    return 	{ "result" => "failure" }

  end

  def rpc_loaded
    ret = {}
    ret[:plugins] = []
    self.framework.plugins.each do  |plugin|
      ret[:plugins] << plugin.name
    end
    ret
  end

end
end
end
