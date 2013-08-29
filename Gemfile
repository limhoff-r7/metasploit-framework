source 'http://rubygems.org'

# Need 3+ for ActiveSupport::Concern
gem 'activesupport', '>= 3.0.0'
# Needed for some admin modules (scrutinizer_add_user.rb)
gem 'json'
# Used for Metasploit::Framework::* ActiveModels that mirror Mdm::* ActiveRecord
# models when the database is not active.
# @note the version requirement should match the version requirement for
#   metasploit_data_model's dependency on metasploit-model so that the version
#   of metasploit-model is the same without or without the db group installed.
# @todo change to `gem 'metasploit-model', '~> X.Y.Z'`` when version X.Y.Z is released to rubygems
gem 'metasploit-model', :git => 'git://github.com/rapid7/metasploit-model.git', :tag => 'v0.5.0.module-caching'
# Needed by msfgui and other rpc components
gem 'msgpack'
# Needed by anemone crawler
gem 'nokogiri'
# Needed by anemone crawler
gem 'robots'
# Needed by db.rb and Msf::Exploit::Capture
gem 'packetfu', '1.1.8'

group :db do
	# Needed for Msf::DbManager
	gem 'activerecord'
	# Database models shared between framework and Pro.
	# @todo change to `gem 'metasploit_data_models', '~> X.Y.Z' when version X.Y.Z is released to rubygems`
	gem 'metasploit_data_models', :git => 'git://github.com/rapid7/metasploit_data_models.git', :tag => 'v0.40.3.module-caching'
	# Needed for module caching in Mdm::ModuleDetails
	gem 'pg', '>= 0.11'
end


group :development do
	# Markdown formatting for yard
	gem 'redcarpet'
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

group :memory do
	gem 'axiom-memory-adapter'
	gem 'rom', '~> 0.1.0'
end

group :pcap do
  gem 'network_interface', '~> 0.0.1'
	# For sniffer and raw socket modules
	gem 'pcaprub'
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
