module Metasploit::Framework::Creation::Service
  # @note Caller is responsible for saving the returned `Mdm::Service`.
  #
  # Returns thre first `Mdm::Service` on {#host} with `Mdm::Service#port` equal to {#exploit_instance}'s RPORT.
  #
  # @return [Mdm::Service] if {#exploit_instance} supports RPORT and it is set.
  # @return [nil] otherwise
  def service
    unless instance_variable_defined? :@service
      @service = nil

      if host
        if exploit_instance.options['RPORT']
          port = exploit_instance.datastore['RPORT']

          if port
            @service = host.services.where(
                port: port,
                # all code paths I could find end up with being 'tcp'.  That doesn't seem right.
                proto: 'tcp'
            ).first_or_initialize
          end
        end
      end
    end

    @service
  end
end