# Use require for ActiveSupport::Dependencies since we don't use use the unloading mechanism
# @todo Use ActiveSupport::Dependencies unloading mechanism to eliminate need to restart msfconsole when developing core code
# @see https://github.com/rails/rails/blob/64226302d82493d9bf67aa9e4fa52b4e0269ee3d/activesupport/lib/active_support/dependencies.rb#L33

ENV['NO_RELOAD'] = 'true'

#
# Use bundler to load dependencies
#

ENV['BUNDLE_GEMFILE'] ||= ::File.expand_path(::File.join(::File.dirname(__FILE__), "..", "Gemfile"))
begin
  require 'bundler/setup'
rescue ::LoadError
  $stderr.puts "[*] Metasploit requires the Bundler gem to be installed"
  $stderr.puts "    $ gem install bundler"
  exit(0)
end
