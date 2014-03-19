shared_examples_for 'Msf::Logging tracker' do
  around(:each) do |example|
    example.run

    count = 0

    Msf::Logging.sources.each do |source|
      sink = $dispatcher[source]

      if sink
        $stderr.puts "#{source} logging source is still connected to #{sink}"

        count += 1
      end
    end

    if count > 0
      $stderr.puts "Use `include_context 'Msf::Logging'` to teardown sources from #{example.metadata.full_description}"
    end
  end
end