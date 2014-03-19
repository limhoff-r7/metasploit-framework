module Metasploit::Framework::Spec::Logging
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.after(:all) do |config|
          count = 0

          Msf::Logging.sources.each do |source|
            sink = $dispatcher[source]

            if sink
              $stderr.puts "#{source} logging source is still connected to #{sink}."

              count += 1
            end
          end

          if count > 0
            $stderr.puts "Use `include_context 'Msf::Logging' tracker` to determine which examples aren't calling Msf::Logging.teardown"
          end
        end
      end
    end
  end
end