source 'http://rubygems.org'

# Need 3+ for ActiveSupport::Concern
gem 'activesupport', '>= 3.0.0'
# Needed for some admin modules (scrutinizer_add_user.rb)
gem 'json'
# Needed by anemone crawler
gem 'nokogiri'
# Needed by anemone crawler
gem 'robots'

# Gems that are only compatible with jruby
platform :jruby do
  # Needed by msfgui and other rpc components
	gem 'msgpack-jruby'

	group :development do
		# Markdown formatting for yard.
		# Equivalent to redcarpet for ruby.
		gem 'kramdown'
	end
end

# Gems that are incompatible with jruby
platform :ruby do
  # Needed by msfgui and other rpc components
	gem 'msgpack'

	group :development do
		# Markdown formatting for yard
		gem 'redcarpet'
	end

	group :pcap do
		# For sniffer and raw socket modules
		# pcaprub claims JRuby compatibility, but only if C extensions are enabled
		# for JRuby, which are planned to be removed in the future
		# (https://github.com/jruby/jruby/wiki/C-Extension-Alternatives)
		gem 'pcaprub'
	end
end

group :db do
	# Needed for Msf::DbManager.
	# Include explicitly since ActiveRecord::Base references are made outside of
	# metasploit_data_models, but don't include database driver since
	# metasploit_data_models chooses it to be compatible with migrations
	# metasploit_data_models includes.  This also has the benefit of
	# metasploit_data_models being the only thing that has to deal with ruby vs
	# jruby for the database.
	gem 'activerecord'
	# Database models shared between framework and Pro.
	gem 'metasploit_data_models', '~> 0.14.3'
end


group :development do
	# generating documentation
	gem 'yard'
end

group :development, :test do
	# supplies factories for producing model instance for specs
	# Version 4.1.0 or newer is needed to support generate calls without the
	# 'FactoryGirl.' in factory definitions syntax.
	gem 'factory_girl', '>= 4.1.0'
	# running documentation generation tasks and rspec tasks
	gem 'rake'
end

group :test do
	# Removes records from database created during tests.  Can't use rspec-rails'
	# transactional fixtures because multiple connections are in use so
	# transactions won't work.
	gem 'database_cleaner'
	# testing framework
	gem 'rspec', '>= 2.12'
	# add matchers from shoulda, such as query_the_database, which is useful for
	# testing that the Msf::DBManager activation is respected.
	gem 'shoulda-matchers'
	# code coverage for tests
	# any version newer than 0.5.4 gives an Encoding error when trying to read the source files.
	gem 'simplecov', '0.5.4', :require => false
	# Manipulate Time.now in specs
	gem 'timecop'
end
