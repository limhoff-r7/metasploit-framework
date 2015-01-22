# -*- coding: binary -*-
require 'msf/core'
require 'fastlib'
require 'pathname'

module Msf

###
#
# Upper management decided to throw in some middle management
# because the modules were getting out of hand.  This bad boy
# takes care of the work of managing the interaction with
# modules in terms of loading and instantiation.
#
# TODO:
#
#   - add unload support
#
###
class ModuleManager < ModuleSet
	require 'msf/core/module_manager/cache'
	require 'msf/core/module_manager/loading'
	require 'msf/core/module_manager/module_paths'
	require 'msf/core/module_manager/module_sets'
	require 'msf/core/module_manager/reloading'

	include Msf::ModuleManager::Cache
	include Msf::ModuleManager::Loading
	include Msf::ModuleManager::ModulePaths
	include Msf::ModuleManager::ModuleSets
	include Msf::ModuleManager::Reloading

	require 'msf/core/payload_set'

	include Framework::Offspring

	#
	# Initializes an instance of the overall module manager using the supplied
	# framework instance. The types parameter can be used to only load specific
	# module types on initialization
	#
	def initialize(framework,types=MODULE_TYPES)
		self.module_paths         = []
		self.module_sets          = {}
		self.module_failed        = {}
		self.enabled_types        = {}
		self.framework            = framework
		self.cache                = {}

		types.each { |type|
			init_module_set(type)
		}

		super(nil)
	end

	#
	# Creates a module using the supplied name.
	#
	def create(name)
		# Check to see if it has a module type prefix.  If it does,
		# try to load it from the specific module set for that type.
		if (md = name.match(/^(#{MODULE_TYPES.join('|')})\/(.*)$/))
			module_sets[md[1]].create(md[2])
		# Otherwise, just try to load it by name.
		else
			super
		end
	end

	#
	# Accessors by module type
	#

	def register_type_extension(type, ext)
	end

protected



	attr_accessor :modules # :nodoc:
end

end

