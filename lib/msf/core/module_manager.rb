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
	require 'msf/core/module_manager/module_paths'
	requore 'msf/core/module_manager/module_sets'

	include Msf::ModuleManager::Cache
	include Msf::ModuleManager::ModulePaths
	include Msf::ModuleManager::ModuleSets

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

	#
	# Returns the set of modules that failed to load.
	#
	def failed
		return module_failed
	end

	def register_type_extension(type, ext)
	end

	#
	# Reloads modules from all module paths
	#
	def reload_modules

		self.module_history = {}
		self.clear

		self.enabled_types.each_key do |type|
			module_sets[type].clear
			init_module_set(type)
		end

		# The number of loaded modules in the following categories:
		# auxiliary/encoder/exploit/nop/payload/post
		count = 0
		module_paths.each do |path|
			mods = load_modules(path, true)
			mods.each_value {|c| count += c}
		end

		rebuild_cache

		count
	end

	#
	# Reloads the module specified in mod.  This can either be an instance of a
	# module or a module class.
	#
	def reload_module(mod)
		omod    = mod
		refname = mod.refname
		ds      = mod.datastore

		dlog("Reloading module #{refname}...", 'core')

		# Set the target file
		file = mod.file_path
		wrap = ::Module.new

		# Load the module into a new Module wrapper
		begin
			wrap.module_eval(load_module_source(file), file)
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[mod.file_path] = errmsg
					return false
				end
			end
		rescue ::Exception => e

			# Hide eval errors when the module version is not compatible
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to reload module from #{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[mod.file_path] = errmsg
					return
				end
			end

			errmsg = "Failed to reload module from #{file}: #{e.class} #{e}"
			elog(errmsg)
			self.module_failed[mod.file_path] = errmsg
			return
		end

		added = nil
		::Msf::Framework::Major.downto(1) do |major|
			if wrap.const_defined?("Metasploit#{major}")
				added = wrap.const_get("Metasploit#{major}")
				break
			end
		end

		if not added
			errmsg = "Reloaded file did not contain a valid module (#{file})."
			elog(errmsg)
			self.module_failed[mod.file_path] = errmsg
			return nil
		end

		self.module_failed.delete(mod.file_path)

		# Remove the original reference to this module
		self.delete(mod.refname)

		# Indicate that the module is being loaded again so that any necessary
		# steps can be taken to extend it properly.
		on_module_load(added, mod.type, refname, {
			'files' => [ mod.file_path ],
			'noup'  => true})

		# Create a new instance of the module
		if (mod = create(refname))
			mod.datastore.update(ds)
		else
			elog("Failed to create instance of #{refname} after reload.", 'core')
			# Return the old module instance to avoid a strace trace
			return omod
		end

		# Let the specific module sets have an opportunity to handle the fact
		# that this module was reloaded.
		module_sets[mod.type].on_module_reload(mod)

		# Rebuild the cache for just this module
		rebuild_cache(mod)

		mod
	end

	#
	# Overrides the module set method for adding a module so that some extra
	# steps can be taken to subscribe the module and notify the event
	# dispatcher.
	#
	def add_module(mod, name, file_paths)
		# Call the module set implementation of add_module
		dup = super

		# Automatically subscribe a wrapper around this module to the necessary
		# event providers based on whatever events it wishes to receive.  We
		# only do this if we are the module manager instance, as individual
		# module sets need not subscribe.
		auto_subscribe_module(dup)

		# Notify the framework that a module was loaded
		framework.events.on_module_load(name, dup)
	end

	#
	# Read the module code from the file on disk
	#
	def load_module_source(file)
		::File.read(file, ::File.size(file))
	end

	def has_module_file_changed?(file)
		begin 
			cfile = self.cache[file] 
			return true if not cfile

			# Payloads can't be cached due to stage/stager matching
			return true if cfile[:mtype] == "payload"
			return cfile[:mtime].to_i != ::File.mtime(file).to_i
		rescue ::Errno::ENOENT
			return true
		end
	end

	def has_archive_file_changed?(arch, file)
		begin 		
			cfile = self.cache[file]
			return true if not cfile

			# Payloads can't be cached due to stage/stager matching
			return true if cfile[:mtype] == "payload"

			return cfile[:mtime].to_i != ::File.mtime(file).to_i
		rescue ::Errno::ENOENT
			return true
		end
	end

	def demand_load_module(mtype, mname)
		n = self.cache.keys.select { |k| 
			self.cache[k][:mtype]   == mtype and 
			self.cache[k][:refname] == mname 
		}.first

		return nil unless n
		m = self.cache[n]

		path = nil
		if m[:file] =~ /^(.*)\/#{m[:mtype]}s?\//
			path = $1
			load_module_from_file(path, m[:file], nil, nil, nil, true)
		else
			dlog("Could not demand load module #{mtype}/#{mname} (unknown base name in #{m[:file]})", 'core', LEV_2)
			nil
		end
	end


protected


	#
	# Load all of the modules from the supplied directory or archive
	#
	def load_modules(bpath, demand = false)
		( bpath =~ /\.fastlib$/ ) ?
			load_modules_from_archive(bpath, demand) :
			load_modules_from_directory(bpath, demand)
	end

	#
	# Load all of the modules from the supplied module path (independent of
	# module type).
	#
	def load_modules_from_directory(bpath, demand = false)
		loaded = {}
		recalc = {}
		counts = {}
		delay  = {}
		ks     = true

		dbase  = ::Dir.new(bpath)
		dbase.entries.each do |ent|
			next if ent.downcase == '.svn'

			path  = ::File.join(bpath, ent)
			mtype = ent.gsub(/s$/, '')

			next if not ::File.directory?(path)
			next if not MODULE_TYPES.include?(mtype)
			next if not enabled_types[mtype]

			# Try to load modules from all the files in the supplied path
			Rex::Find.find(path) do |file|

				# Skip non-ruby files
				next if file[-3,3] != ".rb"

				# Skip unit test files
				next if (file =~ /rb\.(ut|ts)\.rb$/)

				# Skip files with a leading period
				next if file[0,1] == "."

				load_module_from_file(bpath, file, loaded, recalc, counts, demand)
			end
		end

		recalc.each_key do |mtype|
			module_set(mtype).recalculate		
		end

		# Return per-module loaded counts
		return counts
	end


	#
	# Load all of the modules from the supplied fastlib archive
	#
	def load_modules_from_archive(bpath, demand = false)
		loaded = {}
		recalc = {}
		counts = {}
		delay  = {}
		ks     = true

		::FastLib.list(bpath).each do |ent|

			next if ent.index(".svn/")

			mtype, path = ent.split("/", 2)
			mtype.sub!(/s$/, '')

			next if not MODULE_TYPES.include?(mtype)
			next if not enabled_types[mtype]

			# Skip non-ruby files
			next if ent[-3,3] != ".rb"

			# Skip unit test files
			next if (ent =~ /rb\.(ut|ts)\.rb$/)

			# Skip files with a leading period
			next if ent[0,1] == "."

			load_module_from_archive(bpath, ent, loaded, recalc, counts, demand)
		end

		recalc.each_key do |mtype|
			module_set(mtype).recalculate		
		end

		# Return per-module loaded counts
		return counts
	end

	#
	# Loads a module from the supplied file.
	#
	def load_module_from_file(path, file, loaded, recalc, counts, demand = false)

		if not ( demand or has_module_file_changed?(file))
			dlog("Cached module from file #{file} has not changed.", 'core', LEV_2)
			return false
		end

		# Substitute the base path
		path_base = file.sub(path + File::SEPARATOR, '')

		# Derive the name from the path with the exclusion of the .rb
		name = path_base.match(/^(.+?)#{File::SEPARATOR}(.*)(.rb?)$/)[2]

		# Chop off the file name
		path_base.sub!(/(.+)(#{File::SEPARATOR}.+)(.rb?)$/, '\1')

		if (m = path_base.match(/^(.+?)#{File::SEPARATOR}+?/))
			type = m[1]
		else
			type = path_base
		end

		type.sub!(/s$/, '')


		added = nil

		begin
			wrap = ::Module.new
			wrap.module_eval(load_module_source(file), file)
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			# Hide eval errors when the module version is not compatible
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{file} due to error and failed version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
			errmsg = "#{e.class} #{e}"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		::Msf::Framework::Major.downto(1) do |major|
			if wrap.const_defined?("Metasploit#{major}")
				added = wrap.const_get("Metasploit#{major}")
				break
			end
		end

		if not added
			errmsg = "Missing Metasploit class constant"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		# If the module indicates that it is not usable on this system, then we
		# will not try to use it.
		usable = false

		begin
			usable = respond_to?(:is_usable) ? added.is_usable : true
		rescue
			elog("Exception caught during is_usable check: #{$!}")
		end

		if (usable == false)
			ilog("Skipping module in #{file} because is_usable returned false.", 'core', LEV_1)
			return false
		end

		ilog("Loaded #{type} module #{added} from #{file}.", 'core', LEV_2)
		self.module_failed.delete(file)

		# Do some processing on the loaded module to get it into the
		# right associations
		on_module_load(added, type, name, {
			'files' => [ file ],
			'paths' => [ path ],
			'type'  => type })

		# Set this module type as needing recalculation
		recalc[type] = true if (recalc)

		# Append the added module to the hash of file->module
		loaded[file] = added if (loaded)

		# The number of loaded modules this round
		if (counts)
			counts[type] = (counts[type]) ? (counts[type] + 1) : 1
		end

		return true
	end


	#
	# Loads a module from the supplied archive path
	#
	def load_module_from_archive(path, file, loaded, recalc, counts, demand = false)
		
		if not ( demand or has_archive_module_file_changed?(file))
			dlog("Cached module from file #{file} has not changed.", 'core', LEV_2)
			return false
		end

		# Derive the name from the path with the exclusion of the .rb
		name = file.match(/^(.+?)#{File::SEPARATOR}(.*)(.rb?)$/)[2]

		# Chop off the file name
		base = file.sub(/(.+)(#{File::SEPARATOR}.+)(.rb?)$/, '\1')

		if (m = base.match(/^(.+?)#{File::SEPARATOR}+?/))
			type = m[1]
		else
			type = base
		end

		type.sub!(/s$/, '')

		added = nil

		begin
			wrap = ::Module.new
			wrap.module_eval( ::FastLib.load(path, file), file )
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{path}::#{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			# Hide eval errors when the module version is not compatible
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{path}::#{file}due to error and failed version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
			errmsg = "#{e.class} #{e}"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		::Msf::Framework::Major.downto(1) do |major|
			if wrap.const_defined?("Metasploit#{major}")
				added = wrap.const_get("Metasploit#{major}")
				break
			end
		end

		if not added
			errmsg = "Missing Metasploit class constant"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		# If the module indicates that it is not usable on this system, then we
		# will not try to use it.
		usable = false

		begin
			usable = respond_to?(:is_usable) ? added.is_usable : true
		rescue
			elog("Exception caught during is_usable check: #{$!}")
		end

		if (usable == false)
			ilog("Skipping module in #{path}::#{file} because is_usable returned false.", 'core', LEV_1)
			return false
		end

		ilog("Loaded #{type} module #{added} from #{path}::#{file}.", 'core', LEV_2)
		self.module_failed.delete(file)

		# Do some processing on the loaded module to get it into the
		# right associations
		on_module_load(added, type, name, {
			'files' => [ file ],
			'paths' => [ path ],
			'type'  => type })

		# Set this module type as needing recalculation
		recalc[type] = true if (recalc)

		# Append the added module to the hash of file->module
		loaded[file] = added if (loaded)

		# The number of loaded modules this round
		if (counts)
			counts[type] = (counts[type]) ? (counts[type] + 1) : 1
		end

		return true
	end


	#
	# Called when a module is initially loaded such that it can be
	# categorized accordingly.
	#
	def on_module_load(mod, type, name, modinfo)
		# Payload modules require custom loading as the individual files
		# may not directly contain a logical payload that a user would
		# reference, such as would be the case with a payload stager or
		# stage.  As such, when payload modules are loaded they are handed
		# off to a special payload set.  The payload set, in turn, will
		# automatically create all the permutations after all the payload
		# modules have been loaded.
		
		if (type != MODULE_PAYLOAD)
			# Add the module class to the list of modules and add it to the
			# type separated set of module classes
			add_module(mod, name, modinfo)
		end

		module_sets[type].add_module(mod, name, modinfo)
	end

	#
	# This method automatically subscribes a module to whatever event providers
	# it wishes to monitor.  This can be used to allow modules to automatically
	# execute or perform other tasks when certain events occur.  For instance,
	# when a new host is detected, other aux modules may wish to run such
	# that they can collect more information about the host that was detected.
	#
	def auto_subscribe_module(mod)
		# If auto-subscribe has been disabled
		if (framework.datastore['DisableAutoSubscribe'] and
		    framework.datastore['DisableAutoSubscribe'] =~ /^(y|1|t)/)
			return
		end

		# If auto-subscription is enabled (which it is by default), figure out
		# if it subscribes to any particular interfaces.
		inst = nil

		#
		# Exploit event subscriber check
		#
		if (mod.include?(ExploitEvent) == true)
			framework.events.add_exploit_subscriber((inst) ? inst : (inst = mod.new))
		end

		#
		# Session event subscriber check
		#
		if (mod.include?(SessionEvent) == true)
			framework.events.add_session_subscriber((inst) ? inst : (inst = mod.new))
		end
	end

	attr_accessor :modules # :nodoc:
	attr_accessor :module_failed # :nodoc:

end

end

